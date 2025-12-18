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
	"runtime/coverage"
	"syscall"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	felixconfig "github.com/projectcalico/calico/felix/config"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/health"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/prometheus"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/services"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
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
	 * Start health check server
	 */
	healthServer := health.NewHealthServer(
		log.WithFields(logrus.Fields{"component": "health"}),
		*config.GetCalicoVppInitialConfig().HealthCheckPort,
	)
	Go(healthServer.ServeHealth)

	/**
	 * Connect to VPP & wait for it to be up
	 */
	vpp, err := common.CreateVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Fatalf("Cannot create VPP client: %v", err)
	}
	healthServer.SetComponentStatus(health.ComponentVPP, true, "VPP connection established")

	// Once we have the api connection, we know vpp & vpp-manager are running and the
	// state is accurately reported. Wait for vpp-manager to finish the config.
	common.VppManagerInfo, err = common.WaitForVppManager()
	if err != nil {
		log.Fatalf("Vpp Manager not started: %v", err)
	}
	healthServer.SetComponentStatus(health.ComponentVPPManager, true, "VPP Manager ready")

	common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))

	/**
	 * Create the API clients we need
	 */
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
	/* Set log level for bgp server */
	err = bgpServer.SetLogLevel(context.Background(), &apipb.SetLogLevelRequest{Level: *config.BGPLogLevel})
	if err != nil {
		log.Fatalf("failed to set loglevel for bgp %s", err)
	}
	/* Start the BGP listener, it never returns */
	go bgpServer.Serve()

	/**
	 * Start watching nodes & fetch our BGP spec
	 */
	routeWatcher := watchers.NewRouteWatcher(log.WithFields(logrus.Fields{"subcomponent": "host-route-watcher"}))
	linkWatcher := watchers.NewLinkWatcher(common.VppManagerInfo.UplinkStatuses, log.WithFields(logrus.Fields{"subcomponent": "host-link-watcher"}))
	bgpConfigurationWatcher := watchers.NewBGPConfigurationWatcher(clientv3, log.WithFields(logrus.Fields{"subcomponent": "bgp-conf-watch"}))
	prefixWatcher := watchers.NewPrefixWatcher(clientv3, log.WithFields(logrus.Fields{"subcomponent": "prefix-watcher"}))
	peerWatcher := watchers.NewPeerWatcher(clientv3, k8sclient, log.WithFields(logrus.Fields{"subcomponent": "peer-watcher"}))
	bgpFilterWatcher := watchers.NewBGPFilterWatcher(clientv3, k8sclient, log.WithFields(logrus.Fields{"subcomponent": "BGPFilter-watcher"}))
	netWatcher := watchers.NewNetWatcher(vpp, log.WithFields(logrus.Fields{"component": "net-watcher"}))
	routingServer := routing.NewRoutingServer(vpp, bgpServer, log.WithFields(logrus.Fields{"component": "routing"}))
	serviceServer := services.NewServiceServer(vpp, k8sclient, log.WithFields(logrus.Fields{"component": "services"}))
	prometheusServer := prometheus.NewPrometheusServer(vpp, log.WithFields(logrus.Fields{"component": "prometheus"}))
	localSIDWatcher := watchers.NewLocalSIDWatcher(vpp, clientv3, log.WithFields(logrus.Fields{"subcomponent": "localsid-watcher"}))
	felixServer, err := felix.NewFelixServer(vpp, log.WithFields(logrus.Fields{"component": "felix"}))
	if err != nil {
		log.Fatalf("Failed to create felix server %s", err)
	}
	err = felix.InstallFelixPlugin()
	if err != nil {
		log.Fatalf("could not install felix plugin: %s", err)
	}
	connectivityServer := connectivity.NewConnectivityServer(vpp, felixServer, clientv3, log.WithFields(logrus.Fields{"subcomponent": "connectivity"}))
	cniServer := cni.NewCNIServer(vpp, felixServer, log.WithFields(logrus.Fields{"component": "cni"}))

	/* Pubsub should now be registered */

	bgpConf, err := bgpConfigurationWatcher.GetBGPConf()
	if err != nil {
		log.Fatalf("cannot get default BGP config %s", err)
	}

	peerWatcher.SetBGPConf(bgpConf)
	routingServer.SetBGPConf(bgpConf)
	serviceServer.SetBGPConf(bgpConf)

	Go(felixServer.ServeFelix)

	/*
	 * Mark as unhealthy while waiting for Felix config
	 * Kubernetes startup probe handles pod restart if needed
	 */
	healthServer.MarkAsUnhealthy("Waiting for Felix configuration")
	log.Info("Waiting for Felix configuration...")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var felixConfig interface{}
	var ourBGPSpec interface{}
	felixConfigReceived := false
	bgpSpecReceived := false

	for !felixConfigReceived || !bgpSpecReceived {
		select {
		case value := <-felixServer.FelixConfigChan:
			felixConfig = value
			felixConfigReceived = true
			log.Info("FelixConfig received from calico pod")
		case value := <-felixServer.GotOurNodeBGPchan:
			ourBGPSpec = value
			bgpSpecReceived = true
			log.Info("BGP spec received from node add")
		case <-t.Dying():
			log.Error("Tomb dying while waiting for Felix config")
			return
		case <-ticker.C:
			if !felixConfigReceived {
				log.Info("Still waiting for FelixConfig from calico pod...")
			}
			if !bgpSpecReceived {
				log.Info("Still waiting for BGP spec from node add...")
			}
		}
	}

	healthServer.MarkAsHealthy("Felix configuration received")
	healthServer.SetComponentStatus(health.ComponentFelix, true, "Felix config received")
	log.Info("Felix configuration received")

	if ourBGPSpec != nil {
		bgpSpec, ok := ourBGPSpec.(*common.LocalNodeSpec)
		if !ok {
			panic("ourBGPSpec is not *common.LocalNodeSpec")
		}
		prefixWatcher.SetOurBGPSpec(bgpSpec)
		connectivityServer.SetOurBGPSpec(bgpSpec)
		routingServer.SetOurBGPSpec(bgpSpec)
		serviceServer.SetOurBGPSpec(bgpSpec)
		localSIDWatcher.SetOurBGPSpec(bgpSpec)
		netWatcher.SetOurBGPSpec(bgpSpec)
		cniServer.SetOurBGPSpec(bgpSpec)
	}

	if *config.GetCalicoVppFeatureGates().MultinetEnabled {
		Go(netWatcher.WatchNetworks)
		log.Info("Waiting for networks to be listed and synced...")
		select {
		case <-netWatcher.InSync:
			log.Info("Networks synced")
		case <-t.Dying():
			log.Error("Tomb dying while waiting for networks sync")
			return
		}
	}

	if felixConfig != nil {
		felixCfg, ok := felixConfig.(*felixconfig.Config)
		if !ok {
			panic("ourBGPSpec is not *felixconfig.Config")
		}
		cniServer.SetFelixConfig(felixCfg)
		connectivityServer.SetFelixConfig(felixCfg)
	}

	Go(routeWatcher.WatchRoutes)
	Go(linkWatcher.WatchLinks)
	Go(bgpConfigurationWatcher.WatchBGPConfiguration)
	Go(prefixWatcher.WatchPrefix)
	Go(peerWatcher.WatchBGPPeers)
	Go(bgpFilterWatcher.WatchBGPFilters)
	Go(connectivityServer.ServeConnectivity)
	Go(routingServer.ServeRouting)
	Go(serviceServer.ServeService)
	Go(cniServer.ServeCNI)
	Go(prometheusServer.ServePrometheus)

	// watch LocalSID if SRv6 is enabled
	if *config.GetCalicoVppFeatureGates().SRv6Enabled {
		Go(localSIDWatcher.WatchLocalSID)
	}

	healthServer.SetComponentStatus(health.ComponentAgent, true, "Agent ready")
	log.Infof("Agent started")

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan,
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config.HandleUsr2Signal(ctx, log.WithFields(logrus.Fields{"component": "sighdlr"}))

	select {
	case sig := <-sigChan:
		switch sig {
		case os.Interrupt:
			fallthrough
		case syscall.SIGTERM:
			log.Infof("SIG received, exiting")
			t.Kill(errors.Errorf("Caught INT signal"))
		case syscall.SIGUSR1:
			// vpp-manager pokes us with USR1 if VPP terminates
			log.Warnf("Vpp stopped, exiting...")
			t.Kill(errors.Errorf("Caught signal USR1"))
		case syscall.SIGUSR2:
			// the USR2 signal outputs the coverage data,
			// provided the binary is compiled with -cover and
			// GOCOVERDIR is set. This allows us to not require
			// a proper binary termination in order to get coverage data.
			log.Warn("Received SIGUSR2, writing coverage")
			err := coverage.WriteCountersDir(os.Getenv("GOCOVERDIR"))
			if err != nil {
				log.WithError(err).Error("Could not write counters dir")
			}
			err = coverage.WriteMetaDir(os.Getenv("GOCOVERDIR"))
			if err != nil {
				log.WithError(err).Error("Could not write meta dir")
			}
		}
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
