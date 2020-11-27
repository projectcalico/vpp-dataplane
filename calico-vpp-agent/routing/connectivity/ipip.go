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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IpipProvider struct {
	*ConnectivityProviderData
	ipipIfs map[string]*types.IPIPTunnel
}

func NewIPIPProvider(d *ConnectivityProviderData) *IpipProvider {
	return &IpipProvider{d, make(map[string]*types.IPIPTunnel)}
}

func (p *IpipProvider) OnVppRestart() {
	p.ipipIfs = make(map[string]*types.IPIPTunnel)
}

func (p *IpipProvider) RescanState() {
	p.log.Infof("Rescanning existing tunnels")
	p.ipipIfs = make(map[string]*types.IPIPTunnel)
	tunnels, err := p.vpp.ListIPIPTunnels()
	if err != nil {
		p.log.Errorf("Error listing ipip tunnels: %v", err)
	}

	nodeIP4 := p.getNodeIP(false)
	nodeIP6 := p.getNodeIP(true)
	for _, tunnel := range tunnels {
		p.log.Infof("Found existing tunnel: %s", tunnel)
		p.ipipIfs[tunnel.Dst.String()] = tunnel
	}
}

func (p IpipProvider) errorCleanup(tunnel *types.IPIPTunnel) {
	err := p.vpp.DelIPIPTunnel(tunnel)
	if err != nil {
		p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
	}
}

func (p IpipProvider) AddConnectivity(cn *NodeConnectivity) error {
	p.log.Debugf("Adding ipip Tunnel to VPP")
	tunnel, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		tunnel = &types.IPIPTunnel{
			Src: p.getNodeIP(vpplink.IsIP6(cn.NextHop)),
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

		err = p.vpp.InterfaceAdminUp(swIfIndex)
		if err != nil {
			p.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error setting ipip interface up")
		}

		p.ipipIfs[cn.NextHop.String()] = tunnel
	}
	p.log.Infof("IPIP: tunnnel %s ok", tunnel.String())

	p.log.Debugf("Adding ipip tunnel route to %s via swIfIndex %d", cn.Dst.IP.String(), tunnel.SwIfIndex)
	err := p.vpp.RouteAdd(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: tunnel.SwIfIndex,
			Gw:        nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error Adding route to ipip tunnel")
	}
	return nil
}

func (p IpipProvider) DelConnectivity(cn *NodeConnectivity) error {
	tunnel, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		p.log.Infof("IPIP: Del unknown %s", cn.NextHop.String())
		return errors.Errorf("Deleting unknown ipip tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("IPIP: Del ?->%s %d", cn.NextHop.String(), tunnel.SwIfIndex)
	err := p.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: tunnel.SwIfIndex,
			Gw:        nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting ipip tunnel route")
	}
	// We don't delete the interface so keep it in the map
	// delete(p.ipipIfs, cn.NextHop.String())
	return nil
}
