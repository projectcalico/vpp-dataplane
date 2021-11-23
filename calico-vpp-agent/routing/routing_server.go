// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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

package routing

import (
	"fmt"
	"net"
	"sync"

	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	calicov3cli "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	commonAgent "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/connectivity"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/watchers"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"github.com/projectcalico/vpp-dataplane/vpplink"
	"gopkg.in/tomb.v2"
)

const (
	RTPROT_GOBGP = 0x11
)

var (
	server        *Server
	ServerRunning = make(chan int, 1)
)

type Server struct {
	*commonAgent.CalicoVppServerData
	log         *logrus.Entry
	t           tomb.Tomb
	routingData *common.RoutingData

	localAddressMap map[string]*net.IPNet
	ShouldStop      bool

	// Is bgpServer running (s.routingData.BGPServer == nil)
	bgpServerRunningCond *sync.Cond

	felixConfWatcher *watchers.FelixConfWatcher
	bgpWatcher       *watchers.BGPWatcher
	prefixWatcher    *watchers.PrefixWatcher
	kernelWatcher    *watchers.KernelWatcher
	peerWatcher      *watchers.PeerWatcher
	nodeWatcher      *watchers.NodeWatcher
	ipam             watchers.IpamCache

	connectivityServer *connectivity.ConnectivityServer
}

func (s *Server) Clientv3() calicov3cli.Interface {
	return s.routingData.Clientv3
}

func NewServer(vpp *vpplink.VppLink, l *logrus.Entry) (*Server, error) {
	calicoCli, err := calicocli.NewFromEnv()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create calico v1 api client")
	}
	calicoCliV3, err := calicov3cli.NewFromEnv()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create calico v3 api client")
	}
	BGPConf, err := server.getBGPConf(l, calicoCliV3)
	if err != nil {
		return nil, errors.Wrap(err, "error getting BGP configuration")
	}
	l.Infof("Determined BGP configuration: %s", formatBGPConfiguration(BGPConf))

	routingData := common.RoutingData{
		Vpp:                   vpp,
		Client:                calicoCli,
		Clientv3:              calicoCliV3,
		BGPConf:               BGPConf,
		ConnectivityEventChan: make(chan common.ConnectivityEvent, 10),
	}

	server := Server{
		log:                  l,
		routingData:          &routingData,
		localAddressMap:      make(map[string]*net.IPNet),
		bgpServerRunningCond: sync.NewCond(&sync.Mutex{}),
	}

	logLevel, err := logrus.ParseLevel(server.getLogSeverityScreen())
	if err != nil {
		l.WithError(err).Error("Failed to parse loglevel: %s, defaulting to info", server.getLogSeverityScreen())
	} else {
		logrus.SetLevel(logLevel)
	}

	server.ipam = watchers.NewIPAMCache(&routingData, l.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
	server.felixConfWatcher = watchers.NewFelixConfWatcher(&routingData, l.WithFields(logrus.Fields{"subcomponent": "felix-watcher"}))
	server.bgpWatcher = watchers.NewBGPWatcher(&routingData, l.WithFields(logrus.Fields{"subcomponent": "bgp-watcher"}))
	server.prefixWatcher = watchers.NewPrefixWatcher(&routingData, l.WithFields(logrus.Fields{"subcomponent": "prefix-watcher"}))
	server.kernelWatcher = watchers.NewKernelWatcher(&routingData, server.ipam, server.bgpWatcher, l.WithFields(logrus.Fields{"subcomponent": "kernel-watcher"}))
	server.nodeWatcher = watchers.NewNodeWatcher(&routingData, l.WithFields(logrus.Fields{"subcomponent": "node-watcher"}))
	server.peerWatcher = watchers.NewPeerWatcher(&routingData, server.nodeWatcher, l.WithFields(logrus.Fields{"subcomponent": "peer-watcher"}))
	server.connectivityServer = connectivity.NewConnectivityServer(&routingData, server.ipam, server.felixConfWatcher, server.nodeWatcher, l.WithFields(logrus.Fields{"subcomponent": "connectivity"}))

	return &server, nil
}

func (s *Server) serveOne() error {
	s.log.Infof("Routing server started")
	node, err := s.fetchNodeIPs()
	if err != nil {
		return errors.Wrap(err, "cannot get node ips")
	}

	err = s.configureLocalNodeSnat()
	if err != nil {
		return errors.Wrap(err, "cannot configure node snat")
	}

	err = s.createAndStartBGP()
	if err != nil {
		return errors.Wrap(err, "failed to start BGP server")
	}

	if s.routingData.HasV4 {
		err = s.initialPolicySetting(false /* isv6 */)
		if err != nil {
			return errors.Wrap(err, "error configuring initial policies")
		}
	}
	if s.routingData.HasV6 {
		err = s.initialPolicySetting(true /* isv6 */)
		if err != nil {
			return errors.Wrap(err, "error configuring initial policies")
		}
	}
	/* Restore the previous config in case we restarted */
	s.RestoreLocalAddresses()

	/* We should start watching from our GetNodeIPs change call */
	s.t.Go(func() error { return s.nodeWatcher.WatchNodes(node.ResourceVersion) })
	// sync IPAM and call ipamUpdateHandler
	s.t.Go(func() error { return s.ipam.SyncIPAM() })
	// watch prefix assigned and announce to other BGP peers
	s.t.Go(func() error { return s.prefixWatcher.WatchPrefix() })
	// watch BGP peers
	s.t.Go(func() error { return s.peerWatcher.WatchBGPPeers() })
	// watch Felix configuration
	s.t.Go(func() error { return s.felixConfWatcher.WatchFelixConfiguration() })

	// TODO need to watch BGP configurations and restart in case of changes
	// Need to get initial BGP config here, pass it to the watchers that need it,
	// and pass its revision to the BGP config and nodes watchers

	// watch routes from other BGP peers and update FIB
	s.t.Go(func() error { return s.bgpWatcher.WatchBGPPath() })
	s.t.Go(func() error { return s.connectivityServer.ServeConnectivity() })

	// watch routes added by kernel and announce to other BGP peers
	// FIXME : s.t.Go(s.kernelWatcher.WatchKernelRoute())

	s.ipam.WaitReady()
	ServerRunning <- 1
	<-s.t.Dying()
	s.log.Warnf("routing tomb returned %v", s.t.Err())

	err = s.cleanUpRoutes()
	if err != nil {
		return errors.Wrapf(err, "%s, also failed to clean up routes which we injected", s.t.Err())
	}

	err = s.routingData.BGPServer.StopBgp(context.Background(), &bgpapi.StopBgpRequest{})
	if err != nil {
		s.log.Errorf("failed to stop BGP server:", err)
	}
	s.log.Infof("Routing server stopped")
	// This frees the listeners, otherwise NewBgpServer might fail in
	// case of a restart
	s.bgpServerRunningCond.L.Lock()
	s.routingData.BGPServer = nil
	s.bgpServerRunningCond.L.Unlock()
	s.bgpServerRunningCond.Broadcast()
	return nil
}

func formatBGPConfiguration(conf *calicov3.BGPConfigurationSpec) string {
	if conf == nil {
		return "<nil>"
	}
	meshConfig := "<nil>"
	if conf.NodeToNodeMeshEnabled != nil {
		meshConfig = fmt.Sprintf("%v", *conf.NodeToNodeMeshEnabled)
	}
	asn := "<nil>"
	if conf.ASNumber != nil {
		asn = conf.ASNumber.String()
	}
	return fmt.Sprintf(
		"LogSeverityScreen: %s, NodeToNodeMeshEnabled: %s, ASNumber: %s, ListenPort: %d",
		conf.LogSeverityScreen, meshConfig, asn, conf.ListenPort,
	)
}

func (s *Server) getBGPConf(log *logrus.Entry, clientv3 calicov3cli.Interface) (*calicov3.BGPConfigurationSpec, error) {
	defaultBGPConf, err := s.getDefaultBGPConfig(log, clientv3)
	if err != nil {
		return nil, errors.Wrap(err, "error getting default BGP configuration")
	}
	nodeSpecificConf, err := clientv3.BGPConfigurations().Get(context.Background(), "node."+config.NodeName, options.GetOptions{})
	if err != nil {
		switch err.(type) {
		case calicoerr.ErrorResourceDoesNotExist:
			return defaultBGPConf, nil
		default:
			return nil, errors.Wrap(err, "error getting node specific BGP configurations")
		}
	}
	if nodeSpecificConf.Spec.ListenPort != 0 {
		defaultBGPConf.ListenPort = nodeSpecificConf.Spec.ListenPort
	}
	if defaultBGPConf.LogSeverityScreen != "" {
		defaultBGPConf.LogSeverityScreen = nodeSpecificConf.Spec.LogSeverityScreen
	}
	return defaultBGPConf, nil
}

func (s *Server) getDefaultBGPConfig(log *logrus.Entry, clientv3 calicov3cli.Interface) (*calicov3.BGPConfigurationSpec, error) {
	b := true
	conf, err := clientv3.BGPConfigurations().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// Fill in nil values with default ones
		if conf.Spec.NodeToNodeMeshEnabled == nil {
			conf.Spec.NodeToNodeMeshEnabled = &b // Go is great sometimes
		}
		if conf.Spec.ASNumber == nil {
			asn, err := numorstring.ASNumberFromString("64512")
			if err != nil {
				return nil, err
			}
			conf.Spec.ASNumber = &asn
		}
		if conf.Spec.ListenPort == 0 {
			conf.Spec.ListenPort = 179
		}
		if conf.Spec.LogSeverityScreen == "" {
			conf.Spec.LogSeverityScreen = "Info"
		}
		return &conf.Spec, nil
	}
	switch err.(type) {
	case calicoerr.ErrorResourceDoesNotExist:
		log.Debug("No default BGP config found, using default options")
		ret := &calicov3.BGPConfigurationSpec{
			LogSeverityScreen:     "Info",
			NodeToNodeMeshEnabled: &b,
			ListenPort:            179,
		}
		asn, err := numorstring.ASNumberFromString("64512")
		if err != nil {
			return nil, err
		}
		ret.ASNumber = &asn
		return ret, nil
	default:
		return nil, err
	}
}

func (s *Server) getListenPort() uint16 {
	return s.routingData.BGPConf.ListenPort
}

func (s *Server) getLogSeverityScreen() string {
	return s.routingData.BGPConf.LogSeverityScreen
}

func (s *Server) getNodeASN() (*numorstring.ASNumber, error) {
	return s.getPeerASN(config.NodeName)
}

func (s *Server) getPeerASN(host string) (*numorstring.ASNumber, error) {
	node, err := s.routingData.Clientv3.Nodes().Get(context.Background(), host, options.GetOptions{})
	if err != nil {
		return nil, err
	}
	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("host %s is running in policy-only mode")
	}
	asn := node.Spec.BGP.ASNumber
	if asn == nil {
		return s.routingData.BGPConf.ASNumber, nil
	}
	return asn, nil

}

func (s *Server) getGoBGPGlobalConfig() (*bgpapi.Global, error) {
	var routerId string
	var listenAddresses []string = make([]string, 0)
	asn, err := s.getNodeASN()
	if err != nil {
		return nil, errors.Wrap(err, "error getting current node AS number")
	}

	if s.routingData.HasV6 {
		routerId = s.routingData.Ipv6.String()
		listenAddresses = append(listenAddresses, routerId)
	}
	if s.routingData.HasV4 {
		routerId = s.routingData.Ipv4.String() // Override v6 ID if v4 is available
		listenAddresses = append(listenAddresses, routerId)
	}

	if routerId == "" {
		return nil, errors.Wrap(err, "No IPs to make a router ID")
	}
	return &bgpapi.Global{
		As:              uint32(*asn),
		RouterId:        routerId,
		ListenPort:      int32(s.getListenPort()),
		ListenAddresses: listenAddresses,
	}, nil
}

func (s *Server) cleanUpRoutes() error {
	s.log.Tracef("Clean up injected routes")
	filter := &netlink.Route{
		Protocol: RTPROT_GOBGP,
	}
	list4, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	list6, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	for _, route := range append(list4, list6...) {
		netlink.RouteDel(&route)
	}
	return nil
}

func (s *Server) announceLocalAddress(addr *net.IPNet) error {
	s.log.Debugf("Announcing prefix %s in BGP", addr.String())
	path, err := common.MakePath(addr.String(), false /* isWithdrawal */, s.routingData.Ipv4, s.routingData.Ipv6)
	if err != nil {
		return errors.Wrap(err, "error making path to announce")
	}
	// bgpServer might be nil if in the process of restarting
	s.bgpServerRunningCond.L.Lock()
	defer s.bgpServerRunningCond.L.Unlock()
	for s.routingData.BGPServer == nil || s.ShouldStop {
		s.bgpServerRunningCond.Wait()
	}
	if s.ShouldStop {
		return nil
	}
	s.localAddressMap[addr.String()] = addr
	_, err = s.routingData.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error announcing local address")
}

func (s *Server) withdrawLocalAddress(addr *net.IPNet) error {
	s.log.Debugf("Withdrawing prefix %s from BGP", addr.String())
	path, err := common.MakePath(addr.String(), true /* isWithdrawal */, s.routingData.Ipv4, s.routingData.Ipv6)
	if err != nil {
		return errors.Wrap(err, "error making path to withdraw")
	}
	// bgpServer might be nil if in the process of restarting
	s.bgpServerRunningCond.L.Lock()
	defer s.bgpServerRunningCond.L.Unlock()
	for s.routingData.BGPServer == nil || s.ShouldStop {
		s.bgpServerRunningCond.Wait()
	}
	if s.ShouldStop {
		return nil
	}
	delete(s.localAddressMap, addr.String())
	err = s.routingData.BGPServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error withdrawing local address")
}

func (s *Server) RestoreLocalAddresses() {
	for _, addr := range s.localAddressMap {
		err := s.announceLocalAddress(addr)
		if err != nil {
			s.log.Errorf("Local address %s restore failed : %+v", addr.String(), err)
		}
	}
}

func (s *Server) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) {
	var err error
	if isWithdrawal {
		err = s.withdrawLocalAddress(addr)
	} else {
		err = s.announceLocalAddress(addr)
	}
	if err != nil {
		s.log.Errorf("Local address %+v announcing failed : %+v", addr, err)
	}
}

func (s *Server) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	return s.ipam.IPNetNeedsSNAT(prefix)
}

func (s *Server) Serve() {
	s.log.Infof("Serve() routing")
	err := s.felixConfWatcher.GetFelixConfiguration()
	if err != nil {
		s.log.Fatalf("cannot get felix configuration %s", err)
	}
	/* Rescan state might need the nodeIPs set */
	_, err = s.fetchNodeIPs()
	if err != nil {
		s.log.Errorf("cannot get node ips %v", err)
	}
	/* Initialization : rescan state */
	s.routingData.ConnectivityEventChan <- common.ConnectivityEvent{
		Type: common.RescanState,
	}

	for !s.ShouldStop {
		err := s.serveOne()
		if err != nil {
			s.log.Errorf("routing serve returned %v", err)
			if s.routingData.BGPServer != nil {
				s.routingData.BGPServer.StopBgp(context.Background(), &bgpapi.StopBgpRequest{})
			}
		}
	}
}

func (s *Server) Stop() {
	s.ShouldStop = true
	s.bgpServerRunningCond.Broadcast()
	s.t.Kill(errors.Errorf("GracefulStop"))
}

func (s *Server) OnVppRestart() {
	s.log.Infof("Restarting ROUTING")
	// Those should happen first, in case we need to cleanup state
	s.routingData.ConnectivityEventChan <- common.ConnectivityEvent{
		Type: common.VppRestart,
	}
	err := s.configureLocalNodeSnat()
	if err != nil {
		s.log.Errorf("error reconfiguring loical node snat: %v", err)
	}

	s.nodeWatcher.OnVppRestart()

	err = s.ipam.OnVppRestart()
	if err != nil {
		s.log.Errorf("Error re-injecting ipam %v", err)
	}
}
