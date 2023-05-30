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
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	felixconfig "github.com/projectcalico/calico/felix/config"
	calicocli "github.com/projectcalico/calico/libcalico-go/lib/client"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/prometheus"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/services"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"

	watchdog "github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watch_dog"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
)

/*
 * The Calico-VPP agent is responsible for programming VPP based on CNI
 * instructions
 *
 */

var (
	t   tomb.Tomb
	log *logrus.Logger
)

func Go(f func(t *tomb.Tomb) error) {
	if t.Alive() {
		t.Go(func() error {
			err := f(&t)
			if err != nil {
				log.Warnf("Tomb function errored with %s", err)
			}
			return err
		})
	}
}
func CIDebugger(clientv3 calicov3cli.Interface, vpp *vpplink.VppLink, log *logrus.Entry) {
	for {
		time.Sleep(time.Second * 5)
		st, _ := vpp.RunCli("show capo int")
		log.WithFields(logrus.Fields{"subcomponent": "host-route-watcher"})
		log.Infof("::: %s:\n%s", time.Now(), st)
		list, err := clientv3.HostEndpoints().List(context.Background(), options.ListOptions{})
		if err != nil {
			log.Error(err)
		}
		log.Infof("%+v", list)
	}
}
func main() {
	log = logrus.New()

	err := config.LoadConfig(log)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

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
	common.VppManagerInfo, err = common.WaitForVppManager()
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
	go CIDebugger(clientv3, vpp, log.WithFields(logrus.Fields{"subcomponent": "CIDebugger"}))
	/**
	 * Start watching nodes & fetch our BGP spec
	 */
	routeWatcher := watchers.NewRouteWatcher(log.WithFields(logrus.Fields{"subcomponent": "host-route-watcher"}))
	linkWatcher := watchers.NewLinkWatcher(common.VppManagerInfo.UplinkStatuses, log.WithFields(logrus.Fields{"subcomponent": "host-link-watcher"}))
	bgpConfigurationWatcher := watchers.NewBGPConfigurationWatcher(clientv3, log.WithFields(logrus.Fields{"subcomponent": "bgp-conf-watch"}))
	prefixWatcher := watchers.NewPrefixWatcher(client, log.WithFields(logrus.Fields{"subcomponent": "prefix-watcher"}))
	peerWatcher := watchers.NewPeerWatcher(clientv3, k8sclient, log.WithFields(logrus.Fields{"subcomponent": "peer-watcher"}))
	netWatcher := watchers.NewNetWatcher(vpp, log.WithFields(logrus.Fields{"component": "net-watcher"}))
	routingServer := routing.NewRoutingServer(vpp, bgpServer, log.WithFields(logrus.Fields{"component": "routing"}))
	serviceServer := services.NewServiceServer(vpp, k8sclient, log.WithFields(logrus.Fields{"component": "services"}))
	prometheusServer := prometheus.NewPrometheusServer(vpp, log.WithFields(logrus.Fields{"component": "prometheus"}))
	localSIDWatcher := watchers.NewLocalSIDWatcher(vpp, clientv3, log.WithFields(logrus.Fields{"subcomponent": "localsid-watcher"}))
	policyServer, err := policy.NewPolicyServer(vpp, log.WithFields(logrus.Fields{"component": "policy"}))
	if err != nil {
		log.Fatalf("Failed to create policy server %s", err)
	}
	err = policy.InstallFelixPlugin()
	if err != nil {
		log.Fatalf("could not install felix plugin: %s", err)
	}
	connectivityServer := connectivity.NewConnectivityServer(vpp, policyServer, clientv3, log.WithFields(logrus.Fields{"subcomponent": "connectivity"}))
	cniServer := cni.NewCNIServer(vpp, policyServer, log.WithFields(logrus.Fields{"component": "cni"}))

	/* Pubsub should now be registered */

	bgpConf, err := bgpConfigurationWatcher.GetBGPConf()
	if err != nil {
		log.Fatalf("cannot get default BGP config %s", err)
	}

	peerWatcher.SetBGPConf(bgpConf)
	routingServer.SetBGPConf(bgpConf)
	serviceServer.SetBGPConf(bgpConf)

	watchDog := watchdog.NewWatchDog(log.WithFields(logrus.Fields{"component": "watchDog"}), &t)
	Go(policyServer.ServePolicy)
	felixConfig := watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
	ourBGPSpec := watchDog.Wait(policyServer.GotOurNodeBGPchan, "Waiting for bgp spec to be provided on node add")
	// check if the watchDog timer has issued the t.Kill() which would mean we are dead
	if !t.Alive() {
		log.Fatal("WatchDog timed out waiting for config from felix. Exiting...")
	}

	if ourBGPSpec != nil {
		prefixWatcher.SetOurBGPSpec(ourBGPSpec.(*common.LocalNodeSpec))
		connectivityServer.SetOurBGPSpec(ourBGPSpec.(*common.LocalNodeSpec))
		routingServer.SetOurBGPSpec(ourBGPSpec.(*common.LocalNodeSpec))
		serviceServer.SetOurBGPSpec(ourBGPSpec.(*common.LocalNodeSpec))
		localSIDWatcher.SetOurBGPSpec(ourBGPSpec.(*common.LocalNodeSpec))
		netWatcher.SetOurBGPSpec(ourBGPSpec.(*common.LocalNodeSpec))
	}

	if *config.GetCalicoVppFeatureGates().MultinetEnabled {
		Go(netWatcher.WatchNetworks)
		watchDog.Wait(netWatcher.InSync, "Waiting for networks to be listed and synced")
	}

	if felixConfig != nil {
		cniServer.SetFelixConfig(felixConfig.(*felixconfig.Config))
		connectivityServer.SetFelixConfig(felixConfig.(*felixconfig.Config))
	}

	Go(routeWatcher.WatchRoutes)
	Go(linkWatcher.WatchLinks)
	Go(bgpConfigurationWatcher.WatchBGPConfiguration)
	Go(prefixWatcher.WatchPrefix)
	Go(peerWatcher.WatchBGPPeers)
	Go(connectivityServer.ServeConnectivity)
	Go(routingServer.ServeRouting)
	Go(serviceServer.ServeService)
	Go(cniServer.ServeCNI)
	Go(prometheusServer.ServePrometheus)

	// watch LocalSID if SRv6 is enabled
	if *config.GetCalicoVppFeatureGates().SRv6Enabled {
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
	go func() {
		time.Sleep(*config.CalicoVppGracefulShutdownTimeout)
		panic("Graceful shutdown took too long")
	}()
	e := t.Wait()
	log.Infof("Tomb exited with %v", e)
}
