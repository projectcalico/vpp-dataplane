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

package connectivity

import (
	"fmt"

	"github.com/pkg/errors"

	vpptypes "github.com/calico-vpp/vpplink/api/v0"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type IpipProvider struct {
	*ConnectivityProviderData
	ipipIfs    map[string]*vpptypes.IPIPTunnel
	ipipRoutes map[uint32]map[string]bool
}

func NewIPIPProvider(d *ConnectivityProviderData) *IpipProvider {
	return &IpipProvider{d, make(map[string]*vpptypes.IPIPTunnel), make(map[uint32]map[string]bool)}
}

func (p *IpipProvider) EnableDisable(isEnable bool) {
}

func (p *IpipProvider) Enabled(cn *common.NodeConnectivity) bool {
	return true
}

func (p *IpipProvider) RescanState() {
	p.log.Infof("Rescanning existing tunnels")
	p.ipipIfs = make(map[string]*vpptypes.IPIPTunnel)
	tunnels, err := p.vpp.ListIPIPTunnels()
	if err != nil {
		p.log.Errorf("Error listing ipip tunnels: %v", err)
	}

	ip4, ip6 := p.server.GetNodeIPs()
	for _, tunnel := range tunnels {
		if (ip4 != nil && tunnel.Src.Equal(*ip4)) || (ip6 != nil && tunnel.Src.Equal(*ip6)) {
			p.log.Infof("Found existing tunnel: %s", tunnel)
			p.ipipIfs[tunnel.Dst.String()] = tunnel
		}
	}

	indexTunnel := make(map[uint32]*vpptypes.IPIPTunnel)
	for _, tunnel := range p.ipipIfs {
		indexTunnel[tunnel.SwIfIndex] = tunnel
	}
	p.log.Infof("Rescanning existing routes")
	p.ipipRoutes = make(map[uint32]map[string]bool)
	routes, err := p.vpp.GetRoutes(0, false)
	if err != nil {
		p.log.Errorf("Error listing routes: %v", err)
	}
	for _, route := range routes {
		for _, routePath := range route.Paths {
			_, exists := indexTunnel[routePath.SwIfIndex]
			if exists {
				_, found := p.ipipRoutes[routePath.SwIfIndex]
				if !found {
					p.ipipRoutes[routePath.SwIfIndex] = make(map[string]bool)
				}
				p.ipipRoutes[routePath.SwIfIndex][route.Dst.String()] = true
			}
		}
	}
}

func (p *IpipProvider) errorCleanup(tunnel *vpptypes.IPIPTunnel) {
	err := p.vpp.DelIPIPTunnel(tunnel)
	if err != nil {
		p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
	}
}

func (p *IpipProvider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Debugf("connectivity(add) IPIP Tunnel to VPP")
	tunnel, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		tunnel = &vpptypes.IPIPTunnel{
			Dst: cn.NextHop,
		}
		ip4, ip6 := p.server.GetNodeIPs()
		if vpplink.IsIP6(cn.NextHop) && ip6 != nil {
			tunnel.Src = *ip6
		} else if !vpplink.IsIP6(cn.NextHop) && ip4 != nil {
			tunnel.Src = *ip4
		} else {
			return fmt.Errorf("Missing node address")
		}

		p.log.Infof("connectivity(add) create IPIP tunnel=%s", tunnel.String())

		swIfIndex, err := p.vpp.AddIPIPTunnel(tunnel)
		if err != nil {
			return errors.Wrapf(err, "Error adding ipip tunnel %s", tunnel.String())
		}

		err = p.vpp.InterfaceSetUnnumbered(swIfIndex, common.VppManagerInfo.GetMainSwIfIndex())
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error setting ipip tunnel unnumbered")
		}

		// Always enable GSO feature on IPIP tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
		err = p.vpp.EnableGSOFeature(swIfIndex)
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error enabling gso for ipip interface")
		}

		err = p.vpp.CnatEnableFeatures(swIfIndex)
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error enabling nat for ipip interface")
		}

		err = p.vpp.InterfaceAdminUp(swIfIndex)
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error setting ipip interface up")
		}

		p.log.Debugf("Routing pod->node %s traffic into tunnel (swIfIndex %d)", cn.NextHop.String(), swIfIndex)
		err = p.vpp.RouteAdd(&types.Route{
			Dst: common.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
				Gw:        nil,
			}},
			Table: common.PodVRFIndex,
		})
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error adding route to %s in ipip tunnel %d for pods", cn.NextHop.String(), swIfIndex)
		}

		p.ipipIfs[cn.NextHop.String()] = tunnel
		common.SendEvent(common.CalicoVppEvent{
			Type: common.TunnelAdded,
			New:  swIfIndex,
		})
	}
	p.log.Infof("connectivity(add) using IPIP tunnel=%s", tunnel.String())
	p.log.Debugf("connectivity(add) ipip tunnel route dst=%s via tunnel swIfIndex=%d", cn.Dst.IP.String(), tunnel.SwIfIndex)

	route := &types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: tunnel.SwIfIndex,
			Gw:        nil,
		}},
	}
	err := p.vpp.RouteAdd(route)
	if err != nil {
		return errors.Wrapf(err, "Error Adding route to ipip tunnel")
	}
	_, found = p.ipipRoutes[tunnel.SwIfIndex]
	if !found {
		p.ipipRoutes[tunnel.SwIfIndex] = make(map[string]bool)
	}
	p.ipipRoutes[tunnel.SwIfIndex][route.Dst.String()] = true
	return nil
}

func (p *IpipProvider) DelConnectivity(cn *common.NodeConnectivity) error {
	tunnel, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		return errors.Errorf("Deleting unknown ipip tunnel cn=%s", cn.String())
	}
	p.log.Infof("connectivity(del) Removed IPIP connectivity cn=%s swIfIndex=%d", cn.String(), tunnel.SwIfIndex)
	routeToDelete := &types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: tunnel.SwIfIndex,
			Gw:        nil,
		}},
	}
	err := p.vpp.RouteDel(routeToDelete)
	if err != nil {
		return errors.Wrapf(err, "Error deleting ipip tunnel route")
	}

	delete(p.ipipRoutes[tunnel.SwIfIndex], routeToDelete.Dst.String())

	remaining_routes, found := p.ipipRoutes[tunnel.SwIfIndex]
	if !found || len(remaining_routes) == 0 {
		p.log.Infof("connectivity(del) all gone. Deleting IPIP tunnel swIfIndex=%d", tunnel.SwIfIndex)
		err = p.vpp.RouteDel(&types.Route{
			Dst: common.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: tunnel.SwIfIndex,
				Gw:        nil,
			}},
			Table: common.PodVRFIndex,
		})
		if err != nil {
			p.log.Errorf("Error deleting ipip route dst=%s via tunnel swIfIndex=%d %s", cn.NextHop.String(), tunnel.SwIfIndex, err)
		}
		p.log.Infof("connectivity(del) IPIP tunnel=%s", tunnel)
		err := p.vpp.DelIPIPTunnel(tunnel)
		if err != nil {
			p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
		}
		delete(p.ipipIfs, cn.NextHop.String())
		common.SendEvent(common.CalicoVppEvent{
			Type: common.TunnelDeleted,
			Old:  tunnel.SwIfIndex,
		})
	}
	return nil
}
