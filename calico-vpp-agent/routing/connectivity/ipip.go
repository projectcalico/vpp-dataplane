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
	"github.com/pkg/errors"
	commonAgent "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IpipProvider struct {
	*ConnectivityProviderData
	ipipIfs    map[string]*types.IPIPTunnel
	ipipRoutes map[uint32][]*types.Route
}

func NewIPIPProvider(d *ConnectivityProviderData) *IpipProvider {
	return &IpipProvider{d, make(map[string]*types.IPIPTunnel), make(map[uint32][]*types.Route)}
}

func (p *IpipProvider) OnVppRestart() {
	p.ipipIfs = make(map[string]*types.IPIPTunnel)
}

func (p *IpipProvider) Enabled() bool {
	return true
}

func (p *IpipProvider) RescanState() {
	p.log.Infof("Rescanning existing tunnels")
	p.ipipIfs = make(map[string]*types.IPIPTunnel)
	tunnels, err := p.vpp.ListIPIPTunnels()
	if err != nil {
		p.log.Errorf("Error listing ipip tunnels: %v", err)
	}

	nodeIP4 := p.server.GetNodeIP(false)
	nodeIP6 := p.server.GetNodeIP(true)
	for _, tunnel := range tunnels {
		if tunnel.Src.Equal(nodeIP4) || tunnel.Src.Equal(nodeIP6) {
			p.log.Infof("Found existing tunnel: %s", tunnel)
			p.ipipIfs[tunnel.Dst.String()] = tunnel
		}
	}
}

func (p *IpipProvider) errorCleanup(tunnel *types.IPIPTunnel) {
	err := p.vpp.DelIPIPTunnel(tunnel)
	if err != nil {
		p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
	}
}

func (p *IpipProvider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Debugf("Adding ipip Tunnel to VPP")
	tunnel, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		tunnel = &types.IPIPTunnel{
			Src: p.server.GetNodeIP(vpplink.IsIP6(cn.NextHop)),
			Dst: cn.NextHop,
		}
		p.log.Infof("IPIP: Add %s", tunnel.String())

		swIfIndex, err := p.vpp.AddIPIPTunnel(tunnel)
		if err != nil {
			return errors.Wrapf(err, "Error adding ipip tunnel %s", tunnel.String())
		}
		err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error seting ipip tunnel unnumbered")
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
			Dst: commonAgent.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
				Gw:        nil,
			}},
			Table: commonAgent.PodVRFIndex,
		})
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error adding route to %s in ipip tunnel %d for pods", cn.NextHop.String(), swIfIndex)
		}

		p.ipipIfs[cn.NextHop.String()] = tunnel
	}
	p.log.Infof("IPIP: tunnnel %s ok", tunnel.String())

	p.log.Debugf("Adding ipip tunnel route to %s via swIfIndex %d", cn.Dst.IP.String(), tunnel.SwIfIndex)
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
		p.ipipRoutes[tunnel.SwIfIndex] = []*types.Route{route}
	} else {
		p.ipipRoutes[tunnel.SwIfIndex] = append(p.ipipRoutes[tunnel.SwIfIndex], route)
	}
	return nil
}

func (p *IpipProvider) DelConnectivity(cn *common.NodeConnectivity) error {
	tunnel, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		p.log.Infof("IPIP: Del unknown %s", cn.NextHop.String())
		return errors.Errorf("Deleting unknown ipip tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("IPIP: Del ?->%s %d", cn.NextHop.String(), tunnel.SwIfIndex)
	route_to_delete := &types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: tunnel.SwIfIndex,
			Gw:        nil,
		}},
	}
	err := p.vpp.RouteDel(route_to_delete)
	if err != nil {
		return errors.Wrapf(err, "Error deleting ipip tunnel route")
	}

	for index, route := range p.ipipRoutes[tunnel.SwIfIndex] {
		if route.Dst.String() == route_to_delete.Dst.String() {
			p.ipipRoutes[tunnel.SwIfIndex] = append(p.ipipRoutes[tunnel.SwIfIndex][:index], p.ipipRoutes[tunnel.SwIfIndex][index+1:]...)
		}
	}
	remaining_routes, found := p.ipipRoutes[tunnel.SwIfIndex]
	if !found || len(remaining_routes) == 0 {
		p.log.Infof("Deleting tunnel...%s", tunnel)
		err := p.vpp.DelIPIPTunnel(tunnel)
		if err != nil {
			p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
		}
		delete(p.ipipIfs, cn.NextHop.String())
	}
	p.log.Infof("%s", p.ipipIfs)
	return nil
}
