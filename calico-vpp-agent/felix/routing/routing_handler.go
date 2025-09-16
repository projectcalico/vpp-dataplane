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
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

const (
	NetLinkRouteProtocolGoBGP = 0x11
)

type localAddress struct {
	ipNet *net.IPNet
	vni   uint32
}

type RoutingHandler struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	localAddressMap map[string]localAddress

	nodeBGPSpec *common.LocalNodeSpec
}

func NewRoutingHandler(vpp *vpplink.VppLink, cache *cache.Cache, log *logrus.Entry) *RoutingHandler {
	handler := &RoutingHandler{
		log:             log,
		vpp:             vpp,
		cache:           cache,
		localAddressMap: make(map[string]localAddress),
	}

	return handler
}

func (h *RoutingHandler) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	h.nodeBGPSpec = nodeBGPSpec
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

// AnnounceLocalAddress announces a local address to BGP
func (h *RoutingHandler) AnnounceLocalAddress(addr *net.IPNet, vni uint32) error {
	h.log.Debugf("Announcing prefix %s in BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(h.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), false /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*h.cache.BGPConf.ASNumber))
	if err != nil {
		return errors.Wrap(err, "error making path to announce")
	}
	h.localAddressMap[addr.String()] = localAddress{ipNet: addr, vni: vni}

	// Send BGP path event
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPathAdded,
		New:  path,
	})
	return nil
}

// WithdrawLocalAddress withdraws a local address from BGP
func (h *RoutingHandler) WithdrawLocalAddress(addr *net.IPNet, vni uint32) error {
	h.log.Debugf("Withdrawing prefix %s from BGP", addr.String())
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(h.nodeBGPSpec)
	path, err := common.MakePath(addr.String(), true /* isWithdrawal */, nodeIP4, nodeIP6, vni, uint32(*h.cache.BGPConf.ASNumber))
	if err != nil {
		return errors.Wrap(err, "error making path to withdraw")
	}
	delete(h.localAddressMap, addr.String())

	// Send BGP path event
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPathDeleted,
		Old:  path,
	})
	return nil
}

func (h *RoutingHandler) RestoreLocalAddresses() {
	for _, localAddr := range h.localAddressMap {
		err := h.AnnounceLocalAddress(localAddr.ipNet, localAddr.vni)
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

	<-t.Dying()
	h.log.Infof("Routing handler asked to stop")
	return nil
}
