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

	bgpserver "github.com/osrg/gobgp/pkg/server"
	"github.com/pkg/errors"
	calicocli "github.com/projectcalico/calico/libcalico-go/lib/client"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	tomb "gopkg.in/tomb.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/prometheus"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/services"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
)

/*
 * The Calico-VPP agent is responsible for programming VPP based on CNI
 * instructions
 *
 */

var (
	prefixWatcher *watchers.PrefixWatcher
	// kernelWatcher    *watchers.KernelWatcher
	peerWatcher *watchers.PeerWatcher
	nodeWatcher *watchers.NodeWatcher
	ipam        watchers.IpamCache

	connectivityServer *connectivity.ConnectivityServer

	t tomb.Tomb

	log *logrus.Logger
)

func Go(f func(t *tomb.Tomb) error) {
	t.Go(func() error {
		err := f(&t)
		log.Warnf("Tomb error : %s", err)
		return err
	})
}

func main() {
	log = logrus.New()

	err := config.LoadConfig(log)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}
	config.PrintAgentConfig(log)
	log.SetLevel(config.LogLevel)

	err = common.WritePidToFile()
	if err != nil {
		log.Fatalf("Error writing pidfile: %v", err)
	}

	/**
	 * Connect to VPP & wait for it to be up
	 */
	vpp, err := common.CreateVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Fatalf("Cannot create VPP client: %v", err)
	}
	// Once we have the api connection, we know vpp & vpp-manager are running and the
	// state is accurately reported. Wait for vpp-manager to finish the config.
	err = common.WaitForVppManager()
	if err != nil {
		log.Fatalf("Vpp Manager not started: %v", err)
	}

	common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))

	/**
	 * Create the API clients we need
	 */
	client, err := calicocli.NewFromEnv()
	if err != nil {
		log.Fatalf("cannot create calico v1 api client %s", err)
	}
	clientv3, err := calicov3cli.NewFromEnv()
	if err != nil {
		log.Fatalf("cannot create calico v3 api client %s", err)
	}
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("cannot get clusterConfig %s", err)
	}
	k8sclient, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		log.Fatalf("cannot create k8s client %s", err)
	}
	bgpServer := bgpserver.NewBgpServer(
		bgpserver.GrpcListenAddress("localhost:50051"),
		bgpserver.GrpcOption([]grpc.ServerOption{
			grpc.MaxRecvMsgSize(256 << 20),
			grpc.MaxSendMsgSize(256 << 20),
		}),
	)
	/* Start the BGP listener, it never returns */
	go bgpServer.Serve()

	/**
	 * Start watching nodes & fetch our BGP spec
	 */
	bgpConfigurationWatcher := watchers.NewBGPConfigurationWatcher(clientv3, log.WithFields(logrus.Fields{"subcomponent": "bgp-conf-watch"}))
	nodeWatcher := watchers.NewNodeWatcher(vpp, clientv3, log.WithFields(logrus.Fields{"subcomponent": "node-watcher"}))
	ipam := watchers.NewIPAMCache(vpp, clientv3, log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
	prefixWatcher := watchers.NewPrefixWatcher(client, log.WithFields(logrus.Fields{"subcomponent": "prefix-watcher"}))
	// TODO kernelWatcher := watchers.NewKernelWatcher(ipam, log.WithFields(logrus.Fields{"subcomponent": "kernel-watcher"}))
	peerWatcher := watchers.NewPeerWatcher(clientv3, log.WithFields(logrus.Fields{"subcomponent": "peer-watcher"}))
	netWatcher := watchers.NewNetWatcher(vpp, log.WithFields(logrus.Fields{"component": "net-watcher"}))
	connectivityServer = connectivity.NewConnectivityServer(vpp, ipam, clientv3, log.WithFields(logrus.Fields{"subcomponent": "connectivity"}))
	routingServer := routing.NewRoutingServer(vpp, bgpServer, log.WithFields(logrus.Fields{"component": "routing"}))
	serviceServer := services.NewServiceServer(vpp, k8sclient, log.WithFields(logrus.Fields{"component": "services"}))
	prometheusServer := prometheus.NewPrometheusServer(vpp, log.WithFields(logrus.Fields{"component": "prometheus"}))
	cniServer := cni.NewCNIServer(vpp, ipam, log.WithFields(logrus.Fields{"component": "cni"}))
	localSIDWatcher := watchers.NewLocalSIDWatcher(vpp, clientv3, log.WithFields(logrus.Fields{"subcomponent": "localsid-watcher"}))
	policyServer, err := policy.NewPolicyServer(vpp, log.WithFields(logrus.Fields{"component": "policy"}))
	if err != nil {
		log.Fatalf("Failed to create policy server %s", err)
	}

	/* Pubsub should now be registered */

	bgpConf, err := bgpConfigurationWatcher.GetBGPConf()
	if err != nil {
		log.Fatalf("cannot get default BGP config %s", err)
	}

	peerWatcher.SetBGPConf(bgpConf)
	routingServer.SetBGPConf(bgpConf)
	serviceServer.SetBGPConf(bgpConf)

	log.Infof("Waiting for our node's BGP spec...")
	Go(nodeWatcher.WatchNodes)
	ourBGPSpec := nodeWatcher.WaitForOurBGPSpec()

	prefixWatcher.SetOurBGPSpec(ourBGPSpec)
	// kernelWatcher.SetOurBGPSpec(ourBGPSpec)
	connectivityServer.SetOurBGPSpec(ourBGPSpec)
	routingServer.SetOurBGPSpec(ourBGPSpec)
	serviceServer.SetOurBGPSpec(ourBGPSpec)
	policyServer.SetOurBGPSpec(ourBGPSpec)
	localSIDWatcher.SetOurBGPSpec(ourBGPSpec)

	/* Some still depend on ipam being ready */
	log.Infof("Waiting for ipam...")
	Go(ipam.SyncIPAM)
	ipam.WaitReady()

	/**
	 * This should be done in a separated location, but till then, we
	 * still have to wait on the policy server starting
	 */
	log.Infof("Waiting for felix config being present...")

	Go(policyServer.ServePolicy)
	felixConfig := policyServer.WaitForFelixConfig()

	cniServer.SetFelixConfig(felixConfig)
	connectivityServer.SetFelixConfig(felixConfig)

	Go(bgpConfigurationWatcher.WatchBGPConfiguration)
	Go(prefixWatcher.WatchPrefix)
	Go(peerWatcher.WatchBGPPeers)
	Go(connectivityServer.ServeConnectivity)
	if config.MultinetEnabled {
		Go(netWatcher.WatchNetworks)
	}
	Go(routingServer.ServeRouting)
	Go(serviceServer.ServeService)
	Go(cniServer.ServeCNI)
	Go(prometheusServer.ServePrometheus)
	// TODO : Go(kernelWatcher.WatchKernelRoute)

	// watch LocalSID if SRv6 is enabled
	if config.EnableSRv6 {
		Go(localSIDWatcher.WatchLocalSID)
	}

	log.Infof("Agent started")

	interruptSignalChannel := make(chan os.Signal, 2)
	signal.Notify(interruptSignalChannel, os.Interrupt, syscall.SIGTERM)

	usr1SignalChannel := make(chan os.Signal, 2)
	signal.Notify(usr1SignalChannel, syscall.SIGUSR1)

	select {
	case <-usr1SignalChannel:
		/* vpp-manager pokes us with USR1 if VPP terminates */
		log.Warnf("Vpp stopped, exiting...")
		t.Kill(errors.Errorf("Caught signal USR1"))
	case <-interruptSignalChannel:
		log.Infof("SIG received, exiting")
		t.Kill(errors.Errorf("Caught INT signal"))
	case <-t.Dying():
		log.Errorf("tomb Dying %s", t.Err())
	}

	e := t.Wait()
	log.Infof("Tomb exited with %v", e)
}
