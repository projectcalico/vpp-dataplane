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
	infoserver "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore/server"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/services"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logrus.New()
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	err := config.LoadConfig(log)
	if err != nil {
		log.Errorf("Error loading configuration: %v", err)
		return
	}
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
	routingServer, err := routing.NewServer(vpp, serviceServer, log.WithFields(logrus.Fields{"component": "routing"}))
	if err != nil {
		log.Errorf("Failed to create routing server")
		log.Fatal(err)
	}
	cniServer, err := cni.NewServer(
		vpp,
		routingServer,
		serviceServer,
		log.WithFields(logrus.Fields{"component": "cni"}),
	)
	if err != nil {
		log.Errorf("Failed to create CNI server")
		log.Fatal(err)
	}

	go routingServer.Serve()
	<-routing.ServerRunning

	err = cniServer.RescanState()
	if err != nil {
		log.Errorf("Error restoring container connectivity: %v", err)
	}

	go serviceServer.Serve()
	go cniServer.Serve()

	go common.HandleVppManagerRestart(log, vpp, routingServer, cniServer, serviceServer)

	// If grpc API is enabled in the config, starting grpc server and start listening on requests
	var infoSrv infoserver.Info
	if config.InfoStoreEnable {
		infoSrv, err = infoserver.NewInfoServer(cniServer.GetInfoStore(), config.CNIInfoStoreSocket, log.WithFields(logrus.Fields{"component": "infostore"}))
		if err != nil {
			log.Errorf("Failed to start CNI's InfoServer with error: %+v", err)
		} else {
			infoSrv.Start()
		}
	}

	<-signalChannel
	log.Infof("SIGINT received, exiting")
	// Stopping InfoSrv only if it was previously instantiated
	if infoSrv != nil {
		infoSrv.Stop()
	}
	routingServer.Stop()
	cniServer.Stop()
	serviceServer.Stop()
	vpp.Close()
}
