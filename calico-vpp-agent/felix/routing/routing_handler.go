// Copyright (C) 2025 Cisco Systems Inc.
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
	"os"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	NetLinkRouteProtocolGoBGP = 0x11
)

// BGPPathHandler interface for handling BGP path events
type BGPPathHandler interface {
	OnBGPPathAdded(path *bgpapi.Path) error
	OnBGPPathDeleted(path *bgpapi.Path) error
}

type localAddress struct {
	ipNet *net.IPNet
	vni   uint32
}

type RoutingHandler struct {
	log *logrus.Entry
	vpp *vpplink.VppLink

	localAddressMap map[string]localAddress
	ShouldStop      bool

	BGPConf        *calicov3.BGPConfigurationSpec
	nodeBGPSpec    *common.LocalNodeSpec
	bgpPathHandler BGPPathHandler
	felixEventChan chan any
}

func NewRoutingHandler(vpp *vpplink.VppLink, felixEventChan chan any, log *logrus.Entry) *RoutingHandler {
	handler := &RoutingHandler{
		log:             log,
		vpp:             vpp,
		localAddressMap: make(map[string]localAddress),
		felixEventChan:  felixEventChan,
	}

	return handler
}

func (h *RoutingHandler) SetBGPPathHandler(handler BGPPathHandler) {
	h.bgpPathHandler = handler
}

func (h *RoutingHandler) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	h.BGPConf = bgpConf
}

func (h *RoutingHandler) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	h.nodeBGPSpec = nodeBGPSpec
}

// HandleConnectivityAdded handles connectivity addition from BGP watcher
func (h *RoutingHandler) HandleConnectivityAdded(connectivity *common.NodeConnectivity) error {
	h.log.Debugf("Adding route to %s via %s", connectivity.Dst.String(), connectivity.NextHop.String())
	route := &netlink.Route{
		Dst:      &connectivity.Dst,
		Gw:       connectivity.NextHop,
		Protocol: NetLinkRouteProtocolGoBGP,
	}
	err := netlink.RouteAdd(route)
	if err != nil && !os.IsExist(err) {
		h.log.Errorf("cannot add route %+v: %v", route, err)
	}
	return nil
}

// HandleConnectivityDeleted handles connectivity deletion from BGP watcher
func (h *RoutingHandler) HandleConnectivityDeleted(connectivity *common.NodeConnectivity) error {
	h.log.Debugf("Deleting route to %s via %s", connectivity.Dst.String(), connectivity.NextHop.String())
	route := &netlink.Route{
		Dst:      &connectivity.Dst,
		Gw:       connectivity.NextHop,
		Protocol: NetLinkRouteProtocolGoBGP,
	}
	err := netlink.RouteDel(route)
	if err != nil && !os.IsNotExist(err) {
		h.log.Errorf("cannot delete route %+v: %v", route, err)
	}
	return nil
}

// HandleSRv6PolicyAdded handles SRv6 policy addition from BGP watcher
func (h *RoutingHandler) HandleSRv6PolicyAdded(connectivity *common.NodeConnectivity) error {
	srv6tunnel, ok := connectivity.Custom.(*common.SRv6Tunnel)
	if !ok {
		return fmt.Errorf("connectivity.Custom is not a (*common.SRv6Tunnel) %v", connectivity.Custom)
	}
	h.log.Debugf("Adding SRv6 policy %+v", srv6tunnel)
	err := h.vpp.AddSRv6Policy(srv6tunnel.Policy)
	if err != nil {
		h.log.Errorf("Error adding SR policy: %v", err)
	}

	err = h.vpp.AddSRv6Steering(&types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    0,
		Prefix:      types.ToVppPrefix(&net.IPNet{IP: srv6tunnel.Dst, Mask: net.CIDRMask(128, 128)}),
		SwIfIndex:   ^uint32(0),
		Bsid:        types.ToVppIP6Address(srv6tunnel.Bsid),
	})
	if err != nil {
		h.log.Errorf("Error adding SR steer: %v", err)
	}
	return nil
}

// HandleSRv6PolicyDeleted handles SRv6 policy deletion from BGP watcher
func (h *RoutingHandler) HandleSRv6PolicyDeleted(connectivity *common.NodeConnectivity) error {
	srv6tunnel, ok := connectivity.Custom.(*common.SRv6Tunnel)
	if !ok {
		return fmt.Errorf("connectivity.Custom is not a (*common.SRv6Tunnel) %v", connectivity.Custom)
	}
	h.log.Debugf("Deleting SRv6 policy %+v", srv6tunnel)
	err := h.vpp.DelSRv6Steering(&types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    0,
		Prefix:      types.ToVppPrefix(&net.IPNet{IP: srv6tunnel.Dst, Mask: net.CIDRMask(128, 128)}),
		SwIfIndex:   ^uint32(0),
		Bsid:        types.ToVppIP6Address(srv6tunnel.Bsid),
	})
	if err != nil {
		h.log.Errorf("Error deleting SR steer: %v", err)
	}

	err = h.vpp.DelSRv6Policy(srv6tunnel.Policy)
	if err != nil {
		h.log.Errorf("Error deleting SR policy: %v", err)
	}
	return nil
}

func (h *RoutingHandler) cleanUpRoutes() error {
	h.log.Tracef("Clean up injected routes")
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

func (h *RoutingHandler) announceLocalAddress(addr *net.IPNet, vni uint32) error {
	h.log.Debugf("Announcing prefix %s in BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(h.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), false /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*h.BGPConf.ASNumber))
	if err != nil {
		return errors.Wrap(err, "error making path to announce")
	}
	h.localAddressMap[addr.String()] = localAddress{ipNet: addr, vni: vni}

	// Send BGP path event to BGP watcher
	if h.bgpPathHandler != nil {
		return h.bgpPathHandler.OnBGPPathAdded(path)
	}
	return nil
}

func (h *RoutingHandler) withdrawLocalAddress(addr *net.IPNet, vni uint32) error {
	h.log.Debugf("Withdrawing prefix %s from BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(h.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), true /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*h.BGPConf.ASNumber))
	if err != nil {
		return errors.Wrap(err, "error making path to withdraw")
	}
	delete(h.localAddressMap, addr.String())

	// Send BGP path event to BGP watcher
	if h.bgpPathHandler != nil {
		return h.bgpPathHandler.OnBGPPathDeleted(path)
	}
	return nil
}

func (h *RoutingHandler) RestoreLocalAddresses() {
	for _, localAddr := range h.localAddressMap {
		err := h.announceLocalAddress(localAddr.ipNet, localAddr.vni)
		if err != nil {
			h.log.Errorf("Local address %s restore failed : %+v", localAddr.ipNet.String(), err)
		}
	}
}

// Configure SNAT prefixes so that we don't snat traffic going from a local pod to the node
func (h *RoutingHandler) configureLocalNodeSnat() error {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(h.nodeBGPSpec)
	if nodeIP4 != nil {
		err := h.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(*nodeIP4), true)
		if err != nil {
			return errors.Wrapf(err, "error configuring snat prefix for current node (%v)", *nodeIP4)
		}
	}
	if nodeIP6 != nil {
		err := h.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(*nodeIP6), true)
		if err != nil {
			return errors.Wrapf(err, "error configuring snat prefix for current node (%v)", *nodeIP6)
		}
	}
	return nil
}

func (h *RoutingHandler) ServeRoutingHandler(t *tomb.Tomb) (err error) {
	h.log.Infof("Routing handler started")

	/* Clean up any routes we may have injected in previous runs */
	err = h.cleanUpRoutes()
	if err != nil {
		return errors.Wrap(err, "failed to clean up previously injected routes")
	}

	err = h.configureLocalNodeSnat()
	if err != nil {
		return errors.Wrap(err, "cannot configure node snat")
	}

	/* Restore the previous config in case we restarted */
	h.RestoreLocalAddresses()

	h.log.Infof("Routing handler is running")

	for {
		select {
		case <-t.Dying():
			h.log.Infof("Routing handler asked to stop")
			return nil
		case msg := <-h.felixEventChan:
			evt, ok := msg.(common.CalicoVppEvent)
			if !ok {
				continue
			}
			// Only handle LocalPodAddress events from Felix
			if evt.Type == common.LocalPodAddressAdded || evt.Type == common.LocalPodAddressDeleted {
				err := h.handleEvent(evt)
				if err != nil {
					return err
				}
			}
		}
	}
}

func (h *RoutingHandler) handleEvent(evt common.CalicoVppEvent) error {
	/* Note: we will only receive events we ask for when registering the chan */
	switch evt.Type {
	case common.LocalPodAddressAdded:
		networkPod, ok := evt.New.(cni.NetworkPod)
		if !ok {
			return fmt.Errorf("evt.New is not a (cni.NetworkPod) %v", evt.New)
		}
		err := h.announceLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
		if err != nil {
			return err
		}
	case common.LocalPodAddressDeleted:
		networkPod, ok := evt.Old.(cni.NetworkPod)
		if !ok {
			return fmt.Errorf("evt.Old is not a (cni.NetworkPod) %v", evt.Old)
		}
		err := h.withdrawLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
		if err != nil {
			return err
		}
	}
	return nil
}
