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

	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

const (
	NetLinkRouteProtocolGoBGP = 0x11
)

type localAddress struct {
	ipNet *net.IPNet
	vni   uint32
}

type Server struct {
	log *logrus.Entry
	vpp *vpplink.VppLink

	localAddressMap map[string]localAddress
	ShouldStop      bool

	BGPConf    *calicov3.BGPConfigurationSpec
	BGPServer  *bgpserver.BgpServer
	bgpFilters map[string]*calicov3.BGPFilter
	bgpPeers   map[string]*watchers.LocalBGPPeer

	routingServerEventChan chan common.CalicoVppEvent

	nodeBGPSpec *common.LocalNodeSpec
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.BGPConf = bgpConf

	logLevel, err := logrus.ParseLevel(s.getLogSeverityScreen())
	if err != nil {
		s.log.WithError(err).Errorf("Failed to parse loglevel: %s, defaulting to info", s.getLogSeverityScreen())
	} else {
		logrus.SetLevel(logLevel)
	}
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func NewRoutingServer(vpp *vpplink.VppLink, bgpServer *bgpserver.BgpServer, log *logrus.Entry) *Server {
	server := Server{
		log:             log,
		vpp:             vpp,
		BGPServer:       bgpServer,
		localAddressMap: make(map[string]localAddress),

		routingServerEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
		bgpFilters:             make(map[string]*calicov3.BGPFilter),
		bgpPeers:               make(map[string]*watchers.LocalBGPPeer),
	}

	reg := common.RegisterHandler(server.routingServerEventChan, "routing server events")
	reg.ExpectEvents(
		common.LocalPodAddressAdded,
		common.LocalPodAddressDeleted,
		common.BGPPathAdded,
		common.BGPPathDeleted,
		common.BGPDefinedSetAdded,
		common.BGPDefinedSetDeleted,
		common.BGPPeerAdded,
		common.BGPPeerDeleted,
		common.BGPPeerUpdated,
		common.BGPFilterAddedOrUpdated,
		common.BGPFilterDeleted,
	)

	return &server
}

func (s *Server) ServeRouting(t *tomb.Tomb) (err error) {
	s.log.Infof("Routing server started")

	err = s.configureLocalNodeSnat()
	if err != nil {
		return errors.Wrap(err, "cannot configure node snat")
	}

	for t.Alive() {
		nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
		globalConfig, err := s.getGoBGPGlobalConfig(*config.BGPServerMode)
		if err != nil {
			return fmt.Errorf("cannot get global configuration: %v", err)
		}

		err = s.BGPServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{Global: globalConfig})
		if err != nil && *config.BGPServerMode == config.BGPServerModeDualStack && nodeIP4 != nil {
			s.log.Warnf("Failed to start BGP server in dualStack mode: %v. Retrying with IPv4-only listener", err)
			globalConfig, err = s.getGoBGPGlobalConfig(config.BGPServerModeV4Only)
			if err != nil {
				return errors.Wrap(err, "cannot get IPv4-only BGP configuration for fallback")
			}
			err = s.BGPServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{Global: globalConfig})
			if err != nil {
				return errors.Wrap(err, "failed to start BGP server after IPv4-only fallback")
			}
			s.log.Warn("BGP server started in degraded IPv4-only mode because IPv6 listener failed")
		} else if err != nil {
			return errors.Wrap(err, "failed to start BGP server")
		}

		if nodeIP4 != nil {
			err = s.initialPolicySetting(false /* isv6 */)
			if err != nil {
				return errors.Wrap(err, "error configuring initial policies")
			}
		}
		if nodeIP6 != nil {
			err = s.initialPolicySetting(true /* isv6 */)
			if err != nil {
				return errors.Wrap(err, "error configuring initial policies")
			}
		}

		/* Restore the previous config in case we restarted */
		s.RestoreLocalAddresses()

		s.log.Infof("Routing server is running ")

		/* Start watching goBGP */
		err = s.WatchBGPPath(t)
		if err != nil {
			s.log.Error(err)
			return err
		}

		/* watch returned, we shall restart */
		err = s.cleanUpRoutes()
		if err != nil {
			return errors.Wrap(err, "also failed to clean up routes which we injected")
		}

		err = s.BGPServer.StopBgp(context.Background(), &bgpapi.StopBgpRequest{})
		if err != nil {
			s.log.Errorf("failed to stop BGP server: %s", err)
		}
		s.log.Infof("Routing server stopped")

	}
	s.log.Warn("Routing Server returned")

	return nil
}

func (s *Server) getListenPort() uint16 {
	return s.BGPConf.ListenPort
}

func (s *Server) getLogSeverityScreen() string {
	return s.BGPConf.LogSeverityScreen
}

func (s *Server) getGoBGPGlobalConfig(mode config.BGPServerModeType) (*bgpapi.Global, error) {
	var routerID string
	listenAddresses := make([]string, 0)
	asn := s.nodeBGPSpec.ASNumber
	if asn == nil {
		asn = s.BGPConf.ASNumber
	}

	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	useIP4 := nodeIP4 != nil
	useIP6 := nodeIP6 != nil

	switch mode {
	case config.BGPServerModeDualStack:
	case config.BGPServerModeV4Only:
		useIP6 = false
		if !useIP4 {
			return nil, fmt.Errorf("BGP server mode set to v4Only but no IPv4 node address configured")
		}
	default:
		return nil, fmt.Errorf("unsupported BGP server mode %q", mode)
	}

	if useIP6 {
		routerID = nodeIP6.String()
		listenAddresses = append(listenAddresses, routerID)
	}
	if useIP4 {
		routerID = nodeIP4.String() // Override v6 ID if v4 is available
		listenAddresses = append(listenAddresses, routerID)
	}

	if routerID == "" {
		return nil, fmt.Errorf("no IPs to make a router ID")
	}
	return &bgpapi.Global{
		Asn:             uint32(*asn),
		RouterId:        routerID,
		ListenPort:      int32(s.getListenPort()),
		ListenAddresses: listenAddresses,
	}, nil
}

func (s *Server) cleanUpRoutes() error {
	s.log.Tracef("Clean up injected routes")
	filter := &netlink.Route{
		Protocol: NetLinkRouteProtocolGoBGP,
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
		err = netlink.RouteDel(&route)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) announceLocalAddress(addr *net.IPNet, vni uint32) error {
	s.log.Debugf("Announcing prefix %s in BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), false /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*s.BGPConf.ASNumber))
	if err != nil {
		if common.IsMissingNodeIP(err) {
			s.log.WithError(err).Warnf("Skipping BGP announce for %s: node IP missing", addr.String())
			s.localAddressMap[addr.String()] = localAddress{ipNet: addr, vni: vni}
			return nil
		}
		return errors.Wrap(err, "error making path to announce")
	}
	s.localAddressMap[addr.String()] = localAddress{ipNet: addr, vni: vni}
	_, err = s.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error announcing local address")
}

func (s *Server) withdrawLocalAddress(addr *net.IPNet, vni uint32) error {
	s.log.Debugf("Withdrawing prefix %s from BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), true /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*s.BGPConf.ASNumber))
	if err != nil {
		if common.IsMissingNodeIP(err) {
			s.log.WithError(err).Warnf("Skipping BGP withdraw for %s: node IP missing", addr.String())
			delete(s.localAddressMap, addr.String())
			return nil
		}
		return errors.Wrap(err, "error making path to withdraw")
	}
	delete(s.localAddressMap, addr.String())
	err = s.BGPServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error withdrawing local address")
}

func (s *Server) RestoreLocalAddresses() {
	for _, localAddr := range s.localAddressMap {
		err := s.announceLocalAddress(localAddr.ipNet, localAddr.vni)
		if err != nil {
			s.log.Errorf("Local address %s restore failed : %+v", localAddr.ipNet.String(), err)
		}
	}
}
