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

	bgpapi "github.com/osrg/gobgp/api"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

const (
	RTPROT_GOBGP = 0x11
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

	BGPConf   *calicov3.BGPConfigurationSpec
	BGPServer *bgpserver.BgpServer

	routingServerEventChan chan common.CalicoVppEvent

	nodeBGPSpec *oldv3.NodeBGPSpec
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.BGPConf = bgpConf

	logLevel, err := logrus.ParseLevel(s.getLogSeverityScreen())
	if err != nil {
		s.log.WithError(err).Error("Failed to parse loglevel: %s, defaulting to info", s.getLogSeverityScreen())
	} else {
		logrus.SetLevel(logLevel)
	}
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *oldv3.NodeBGPSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func NewRoutingServer(vpp *vpplink.VppLink, bgpServer *bgpserver.BgpServer, log *logrus.Entry) *Server {
	server := Server{
		log:             log,
		vpp:             vpp,
		BGPServer:       bgpServer,
		localAddressMap: make(map[string]localAddress),

		routingServerEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
	}

	reg := common.RegisterHandler(server.routingServerEventChan, "routing server events")
	reg.ExpectEvents(
		common.LocalPodAddressAdded,
		common.LocalPodAddressDeleted,
		common.BGPReloadIP4,
		common.BGPReloadIP6,
		common.BGPPathAdded,
		common.BGPPathDeleted,
		common.BGPDefinedSetAdded,
		common.BGPDefinedSetDeleted,
		common.BGPPeerAdded,
		common.BGPPeerDeleted,
		common.BGPPeerUpdated,
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
		globalConfig, err := s.getGoBGPGlobalConfig()
		if err != nil {
			return fmt.Errorf("cannot get global configuration: %v", err)
		}

		err = s.BGPServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{Global: globalConfig})
		if err != nil {
			return errors.Wrap(err, "failed to start BGP server")
		}

		nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
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
			s.log.Errorf("failed to stop BGP server:", err)
		}
		s.log.Infof("Routing server stopped")

	}
	s.log.Infof("Routing Server returned")

	return nil
}

func (s *Server) getListenPort() uint16 {
	return s.BGPConf.ListenPort
}

func (s *Server) getLogSeverityScreen() string {
	return s.BGPConf.LogSeverityScreen
}

func (s *Server) getGoBGPGlobalConfig() (*bgpapi.Global, error) {
	var routerId string
	var listenAddresses []string = make([]string, 0)
	asn := s.nodeBGPSpec.ASNumber
	if asn == nil {
		asn = s.BGPConf.ASNumber
	}

	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	if nodeIP6 != nil {
		routerId = nodeIP6.String()
		listenAddresses = append(listenAddresses, routerId)
	}
	if nodeIP4 != nil {
		routerId = nodeIP4.String() // Override v6 ID if v4 is available
		listenAddresses = append(listenAddresses, routerId)
	}

	if routerId == "" {
		return nil, fmt.Errorf("No IPs to make a router ID")
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

func (s *Server) announceLocalAddress(addr *net.IPNet, vni uint32) error {
	s.log.Debugf("Announcing prefix %s in BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), false /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*s.BGPConf.ASNumber))
	if err != nil {
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
