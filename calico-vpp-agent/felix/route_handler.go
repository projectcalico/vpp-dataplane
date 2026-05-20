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

package felix

import (
	"net"
	"syscall"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
)

// RouteHandler handles network and IPAM events by updating VPP routing configuration
type RouteHandler struct {
	log          *logrus.Entry
	routeWatcher *watchers.RouteWatcher
}

// NewRouteHandler creates a new RouteHandler instance
func NewRouteHandler(log *logrus.Entry) *RouteHandler {
	return &RouteHandler{
		log:          log,
		routeWatcher: nil,
	}
}

// SetRouteWatcher sets the route watcher for performing route operations
func (h *RouteHandler) SetRouteWatcher(routeWatcher *watchers.RouteWatcher) {
	h.routeWatcher = routeWatcher
}

// OnNetDeleted handles network deletion events
func (h *RouteHandler) OnNetDeleted(netDef *common.NetworkDefinition) error {
	key := netDef.Range
	routes, err := h.getNetworkRoute(key, netDef.PhysicalNetworkName)
	if err != nil {
		h.log.Errorf("Error getting route from network deletion: %v", err)
		return err
	}
	for _, route := range routes {
		err = h.routeWatcher.DelRoute(route)
		if err != nil {
			h.log.Errorf("Cannot delete pool route %s through vpp tap: %v", key, err)
			return err
		}
	}
	return nil
}

// OnNetAddedOrUpdated handles network addition/update events
func (h *RouteHandler) OnNetAddedOrUpdated(netDef *common.NetworkDefinition) error {
	key := netDef.Range
	routes, err := h.getNetworkRoute(key, netDef.PhysicalNetworkName)
	if err != nil {
		h.log.Errorf("Error getting route from network addition/update: %v", err)
		return err
	}
	for _, route := range routes {
		err = h.routeWatcher.AddRoute(route)
		if err != nil {
			h.log.Errorf("Cannot add pool route %s through vpp tap: %v", key, err)
			return err
		}
	}
	return nil
}

// OnIpamConfChanged handles IPAM configuration changes
func (h *RouteHandler) OnIpamConfChanged(oldPool, newPool *proto.IPAMPool) error {
	h.log.Debugf("Received IPAM config update in route handler old:%+v new:%+v", oldPool, newPool)
	if newPool == nil && oldPool != nil {
		routes, err := h.getNetworkRoute(oldPool.Cidr, "")
		if err != nil {
			h.log.Errorf("Error getting route from ipam update: %v", err)
			return err
		}
		for _, route := range routes {
			err = h.routeWatcher.DelRoute(route)
			if err != nil {
				h.log.Errorf("Cannot delete pool route %s through vpp tap: %v", oldPool.Cidr, err)
				return err
			}
		}
	} else if newPool != nil {
		routes, err := h.getNetworkRoute(newPool.Cidr, "")
		if err != nil {
			h.log.Errorf("Error getting route from ipam update: %v", err)
			return err
		}
		for _, route := range routes {
			err = h.routeWatcher.AddRoute(route)
			if err != nil {
				h.log.Errorf("Cannot add pool route %s through vpp tap: %v", newPool.Cidr, err)
				return err
			}
		}
	}
	return nil
}

func (h *RouteHandler) getNetworkRoute(network string, physicalNet string) (route []*netlink.Route, err error) {
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", network)
	}
	var routes []*netlink.Route
	var order int
	for _, uplinkStatus := range common.VppManagerInfo.UplinkStatuses {
		if uplinkStatus.PhysicalNetworkName == physicalNet {
			gw := uplinkStatus.FakeNextHopIP4
			if cidr.IP.To4() == nil {
				gw = uplinkStatus.FakeNextHopIP6
			}
			var priority int
			if uplinkStatus.IsMain {
				priority = 0
			} else {
				order += 1
				priority = order
			}
			routes = append(routes, &netlink.Route{
				Dst:      cidr,
				Gw:       gw,
				Protocol: syscall.RTPROT_STATIC,
				MTU:      watchers.GetUplinkMtu(),
				Priority: priority,
			})
		}
	}
	return routes, nil
}
