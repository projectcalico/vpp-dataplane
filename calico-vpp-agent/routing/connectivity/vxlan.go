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
	// TODO

}

func (p *VXLanProvider) OnVppRestart() {
	p.vxlanIfs = make(map[string]uint32)
	p.configureVXLANNodes()
}

func (p *VXLanProvider) getVXLANVNI() uint32 {
	felixConf := p.server.GetFelixConfig()
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

func (p *VXLanProvider) AddConnectivity(cn *NodeConnectivity) error {
	p.log.Debugf("Adding vxlan Tunnel to VPP")
	nodeIP := p.server.GetNodeIP(vpplink.IsIP6(cn.NextHop))
	felixConf := p.server.GetFelixConfig()

	var vxLanPort uint16
	if felixConf.VXLANPort != nil {
		vxLanPort = uint16(*felixConf.VXLANPort)

	} else {
		vxLanPort = 0
	}

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

func (p *VXLanProvider) DelConnectivity(cn *NodeConnectivity) error {
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
