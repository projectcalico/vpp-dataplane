// Copyright (C) 2019 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/services"
	"github.com/sirupsen/logrus"
)

/*
 * The Calico-VPP agent is responsible for programming VPP based on CNI
 * instructions
 *
 * Server interactions are as follows :
 *
 * CNIServer -> RoutingServer (AnnounceLocalAddress, IPNetNeedsSNAT)
 */

func main() {
	log := logrus.New()
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	err := config.LoadConfig(log)
	if err != nil {
		log.Errorf("Error loading configuration: %v", err)
		return
	}
	config.PrintAgentConfig(log)
	log.SetLevel(config.LogLevel)

	common.InitRestartHandler()
	err = common.WritePidToFile()
	if err != nil {
		log.Errorf("Error writing pidfile: %v", err)
		return
	}

	vpp, err := common.CreateVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Errorf("Cannot create VPP client: %v", err)
		return
	}
	// Once we have the api connection, we know vpp & vpp-manager are running and the
	// state is accurately reported. Wait for vpp-manager to finish the config.
	err = common.WaitForVppManager()
	if err != nil {
		log.Errorf("Vpp Manager not started: %v", err)
		return
	}

	serviceServer, err := services.NewServer(vpp, log.WithFields(logrus.Fields{"component": "services"}))
	if err != nil {
		log.Errorf("Failed to create services server")
		log.Fatal(err)
	}
	routingServer, err := routing.NewServer(vpp, log.WithFields(logrus.Fields{"component": "routing"}))
	if err != nil {
		log.Errorf("Failed to create routing server")
		log.Fatal(err)
	}
	policyServer, err := policy.NewServer(vpp, log.WithFields(logrus.Fields{"component": "policy"}))
	if err != nil {
		log.Errorf("Failed to create policy server")
		log.Fatal(err)
	}
	cniServer, err := cni.NewServer(
		vpp,
		routingServer,
		policyServer,
		log.WithFields(logrus.Fields{"component": "cni"}),
	)
	if err != nil {
		log.Errorf("Failed to create CNI server")
		log.Fatal(err)
	}

	go routingServer.Serve()
	<-routing.ServerRunning

	go policyServer.Serve()
	// Felix Config will be sent by the policy server
	config.WaitForFelixConfig()
	config.PrintAgentConfig(log)

	go serviceServer.Serve()
	go cniServer.Serve()

	go common.HandleVppManagerRestart(log, vpp, routingServer, cniServer, serviceServer, policyServer)

	<-signalChannel
	log.Infof("SIGINT received, exiting")
	routingServer.Stop()
	cniServer.Stop()
	serviceServer.Stop()
	vpp.Close()
}
