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

type VXLanProvider struct {
	*ConnectivityProviderData
	vxlanIfs     map[string]uint32
	ip4NodeIndex uint32
	ip6NodeIndex uint32
}

func NewVXLanProvider(d *ConnectivityProviderData) *VXLanProvider {
	return &VXLanProvider{d, make(map[string]uint32), 0, 0}
}

func (p *VXLanProvider) Enabled() bool {
	return true
}

func (p *VXLanProvider) configureVXLANNodes() error {
	var err error
	p.ip4NodeIndex, err = p.vpp.AddNodeNext("vxlan4-input", "ip4-input")
	if err != nil {
		p.log.Fatal("Couldn't find node id for ip4-input : %v", err)
	}
	p.ip6NodeIndex, err = p.vpp.AddNodeNext("vxlan6-input", "ip6-input")
	if err != nil {
		p.log.Fatal("Couldn't find node id for ip6-input : %v", err)
	}
	return nil
}

func (p *VXLanProvider) RescanState() {
	p.log.Infof("Rescanning existing VXLAN tunnels")
	p.vxlanIfs = make(map[string]uint32)
	tunnels, err := p.vpp.ListVXLanTunnels()
	if err != nil {
		p.log.Errorf("Error listing VXLan tunnels: %v", err)
	}
	nodeIP4 := p.server.GetNodeIP(false)
	nodeIP6 := p.server.GetNodeIP(true)
	for _, tunnel := range tunnels {
		if (tunnel.SrcAddress.Equal(nodeIP4) || tunnel.SrcAddress.Equal(nodeIP6)) &&
			tunnel.Vni == p.getVXLANVNI() && tunnel.DstPort == p.getVXLANPort() && tunnel.SrcPort == p.getVXLANPort() {

			p.log.Infof("Found existing tunnel: %s", tunnel)

			p.vxlanIfs[tunnel.DstAddress.String()] = uint32(tunnel.SwIfIndex)
		}
	}

}

func (p *VXLanProvider) OnVppRestart() {
	p.vxlanIfs = make(map[string]uint32)
	p.configureVXLANNodes()
}

func (p *VXLanProvider) getVXLANVNI() uint32 {
	felixConf := p.GetFelixConfig()
	if felixConf == nil {
		return uint32(config.DefaultVXLANVni)
	}
	if felixConf.VXLANVNI == nil {
		return uint32(config.DefaultVXLANVni)
	}
	if *felixConf.VXLANVNI == 0 {
		return uint32(config.DefaultVXLANVni)
	}
	return uint32(*felixConf.VXLANVNI)
}

func (p *VXLanProvider) getVXLANPort() uint16 {
	felixConf := p.GetFelixConfig()
	if felixConf.VXLANPort != nil {
		return uint16(*felixConf.VXLANPort)
	} else {
		return config.DefaultVXLANPort
	}
}

func (p *VXLanProvider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Debugf("Adding vxlan Tunnel to VPP")
	nodeIP := p.GetNodeIP(vpplink.IsIP6(cn.NextHop))

	vxLanPort := p.getVXLANPort()
	if _, found := p.vxlanIfs[cn.NextHop.String()]; !found {
		p.log.Infof("VXLan: Add %s->%s", nodeIP.String(), cn.Dst.IP.String())
		tunnel := &types.VXLanTunnel{
			SrcAddress:     nodeIP,
			DstAddress:     cn.NextHop,
			SrcPort:        vxLanPort,
			DstPort:        vxLanPort,
			Vni:            p.getVXLANVNI(),
			DecapNextIndex: p.ip4NodeIndex,
		}
		if vpplink.IsIP6(cn.NextHop) {
			tunnel.DecapNextIndex = p.ip6NodeIndex
		}
		swIfIndex, err := p.vpp.AddVXLanTunnel(tunnel)
		if err != nil {
			return errors.Wrapf(err, "Error adding vxlan tunnel %s -> %s", nodeIP.String(), cn.NextHop.String())
		}
		err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error seting vxlan tunnel unnumbered")
		}

		// Always enable GSO feature on VXLan tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
		err = p.vpp.EnableGSOFeature(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error enabling gso for vxlan interface")
		}

		err = p.vpp.CnatEnableFeatures(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error enabling nat for vxlan interface")
		}

		err = p.vpp.InterfaceAdminUp(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error setting vxlan interface up")
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
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error adding route to %s in ipip tunnel %d for pods", cn.NextHop.String(), swIfIndex)
		}

		p.vxlanIfs[cn.NextHop.String()] = swIfIndex
		p.log.Infof("VXLan: Added ?->%s %d", cn.Dst.IP.String(), swIfIndex)
	}
	swIfIndex := p.vxlanIfs[cn.NextHop.String()]
	p.log.Infof("VXLan: Added ?->%s %d", cn.Dst.IP.String(), swIfIndex)

	p.log.Debugf("Adding vxlan tunnel route to %s via swIfIndex %d", cn.Dst.IP.String(), swIfIndex)
	return p.vpp.RouteAdd(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nodeIP,
		}},
	})
}

func (p *VXLanProvider) DelConnectivity(cn *common.NodeConnectivity) error {
	swIfIndex, found := p.vxlanIfs[cn.NextHop.String()]
	if !found {
		p.log.Infof("VXLan: Del unknown %s", cn.NextHop.String())
		return errors.Errorf("Deleting unknown vxlan tunnel %s", cn.NextHop.String())
	}
	/* TODO: delete tunnel */
	nodeIP := p.server.GetNodeIP(vpplink.IsIP6(cn.NextHop))
	p.log.Infof("VXLan: Del ?->%s %d", cn.NextHop.String(), swIfIndex)
	err := p.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nodeIP,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting vxlan tunnel route")
	}
	delete(p.vxlanIfs, cn.NextHop.String())
	return nil
}
