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
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type VXLanProvider struct {
	*ConnectivityProviderData
	vxlanIfs     map[string]types.VXLanTunnel
	vxlanRoutes  map[uint32]map[string]bool
	ip4NodeIndex uint32
	ip6NodeIndex uint32

	netsLoopbacks map[uint32]bool
}

func NewVXLanProvider(d *ConnectivityProviderData) *VXLanProvider {
	return &VXLanProvider{d, make(map[string]types.VXLanTunnel), make(map[uint32]map[string]bool), 0, 0, make(map[uint32]bool)}
}

func (p *VXLanProvider) EnableDisable(isEnable bool) () {
}

func (p *VXLanProvider) Enabled(cn *common.NodeConnectivity) bool {
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
	p.configureVXLANNodes()
	p.vxlanIfs = make(map[string]types.VXLanTunnel)
	tunnels, err := p.vpp.ListVXLanTunnels()
	if err != nil {
		p.log.Errorf("Error listing VXLan tunnels: %v", err)
	}
	ip4, ip6 := p.server.GetNodeIPs()
	for _, tunnel := range tunnels {
		if (ip4 != nil && tunnel.SrcAddress.Equal(*ip4)) || (ip6 != nil && tunnel.SrcAddress.Equal(*ip6)) {
			if tunnel.Vni == p.getVXLANVNI() && tunnel.DstPort == p.getVXLANPort() && tunnel.SrcPort == p.getVXLANPort() {
				p.log.Infof("Found existing tunnel: %s", tunnel)
				p.vxlanIfs[tunnel.DstAddress.String()+"-"+fmt.Sprint(tunnel.Vni)] = tunnel
			}
		}
	}

	tunnelBySwIfIndex := make(map[uint32]bool)
	for _, tunnel := range p.vxlanIfs {
		tunnelBySwIfIndex[tunnel.SwIfIndex] = true
	}
	p.log.Infof("Rescanning existing routes")
	p.vxlanRoutes = make(map[uint32]map[string]bool)
	routes, err := p.vpp.GetRoutes(0, false)
	if err != nil {
		p.log.Errorf("Error listing routes: %v", err)
	}
	for _, route := range routes {
		for _, routePath := range route.Paths {
			_, exists := tunnelBySwIfIndex[routePath.SwIfIndex]
			if exists {
				_, found := p.vxlanRoutes[routePath.SwIfIndex]
				if !found {
					p.vxlanRoutes[routePath.SwIfIndex] = make(map[string]bool)
				}
				p.vxlanRoutes[routePath.SwIfIndex][route.Dst.String()] = true
			}
		}
	}
}

func (p *VXLanProvider) getVXLANVNI() uint32 {
	felixConfig := p.GetFelixConfig()
	if felixConfig.VXLANVNI == 0 {
		return uint32(config.DefaultVXLANVni)
	}
	return uint32(felixConfig.VXLANVNI)
}

func (p *VXLanProvider) getVXLANPort() uint16 {
	felixConfig := p.GetFelixConfig()
	if felixConfig.VXLANPort == 0 {
		return config.DefaultVXLANPort
	}
	return uint16(felixConfig.VXLANPort)
}

func (p *VXLanProvider) getNodeIpForConnectivity(cn *common.NodeConnectivity) (nodeIP net.IP, err error) {
	ip4, ip6 := p.server.GetNodeIPs()
	if vpplink.IsIP6(cn.NextHop) && ip6 != nil {
		return *ip6, nil
	} else if !vpplink.IsIP6(cn.NextHop) && ip4 != nil {
		return *ip4, nil
	} else {
		return nodeIP, fmt.Errorf("Missing node address")
	}
}

func (p *VXLanProvider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Debugf("Adding vxlan Tunnel to VPP")
	nodeIP, err := p.getNodeIpForConnectivity(cn)
	if err != nil {
		return err
	}
	familyIdx := 0
	if vpplink.IsIP6(cn.Dst.IP) {
		familyIdx = 1
	}
	if cn.Vni != 0 {
		_, found := p.netsLoopbacks[cn.Vni]
		if !found {
			err := p.vpp.SetInterfaceVRF(p.server.networks[cn.Vni].LoopbackSwIfIndex, p.server.networks[cn.Vni].VRF.Tables[familyIdx], familyIdx == 1)
			if err != nil {
				return errors.Wrapf(err, "Error setting loopback %d in network vrf", p.server.networks[cn.Vni].LoopbackSwIfIndex)
			}
			ip4, ip6 := p.GetNodeIPs()
			if familyIdx == 0 {
				err = p.vpp.AddInterfaceAddress(p.server.networks[cn.Vni].LoopbackSwIfIndex, common.ToMaxLenCIDR(*ip4))
				if err != nil {
					return errors.Wrapf(err, "Error adding address %s to pod loopback interface", *ip4)
				}
			} else {
				err = p.vpp.AddInterfaceAddress(p.server.networks[cn.Vni].LoopbackSwIfIndex, common.ToMaxLenCIDR(*ip6))
				if err != nil {
					return errors.Wrapf(err, "Error adding address %s to pod loopback interface", *ip6)
				}
			}
			p.netsLoopbacks[cn.Vni] = true
		}
	}
	_, found := p.vxlanIfs[cn.NextHop.String()+"-"+fmt.Sprint(cn.Vni)]
	if !found {
		p.log.Infof("connectivity(add) VXLan %s->%s(VNI:%d)", nodeIP.String(), cn.NextHop.String(), cn.Vni)
		tunnel := &types.VXLanTunnel{
			SrcAddress:     nodeIP,
			DstAddress:     cn.NextHop,
			SrcPort:        p.getVXLANPort(),
			DstPort:        p.getVXLANPort(),
			Vni:            p.getVXLANVNI(),
			DecapNextIndex: p.ip4NodeIndex,
		}
		if cn.Vni != 0 {
			tunnel.Vni = cn.Vni
		}
		if vpplink.IsIP6(cn.NextHop) {
			tunnel.DecapNextIndex = p.ip6NodeIndex
		}
		swIfIndex, err := p.vpp.AddVXLanTunnel(tunnel)
		if err != nil {
			return errors.Wrapf(err, "Error adding vxlan tunnel %s -> %s", nodeIP.String(), cn.NextHop.String())
		}
		if cn.Vni == 0 {
			err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
			if err != nil {
				// TODO : delete tunnel
				return errors.Wrapf(err, "Error setting vxlan tunnel unnumbered")
			}
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

		if cn.Vni == 0 {
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
				// TODO : delete tunnel
				return errors.Wrapf(err, "Error adding route to %s in ipip tunnel %d for pods", cn.NextHop.String(), swIfIndex)
			}
		}

		p.vxlanIfs[cn.NextHop.String()+"-"+fmt.Sprint(cn.Vni)] = *tunnel
		p.log.Infof("connectivity(add) VXLan Added tunnel=%s", tunnel)
		common.SendEvent(common.CalicoVppEvent{
			Type: common.TunnelAdded,
			New:  swIfIndex,
		})
		if cn.Vni != 0 {
			vrfIndex := p.server.networks[cn.Vni].VRF.Tables[familyIdx]
			p.log.Infof("connectivity(add) set vxlan interface %d in vrf %d", tunnel.SwIfIndex, vrfIndex)
			err := p.vpp.SetInterfaceVRF(tunnel.SwIfIndex, vrfIndex, vpplink.IsIP6(cn.Dst.IP))
			if err != nil {
				return err
			}

			p.log.Infof("connectivity(add) set vxlan interface unnumbered")
			err = p.vpp.InterfaceSetUnnumbered(tunnel.SwIfIndex, p.server.networks[cn.Vni].LoopbackSwIfIndex)
			if err != nil {
				// TODO : delete tunnel
				return errors.Wrapf(err, "Error setting vxlan tunnel unnumbered")
			}
		}
	}
	tunnel := p.vxlanIfs[cn.NextHop.String()+"-"+fmt.Sprint(cn.Vni)]

	var table uint32
	if cn.Vni == 0 {
		p.log.Infof("connectivity(add) vxlan route dst=%s via swIfIndex=%d", cn.Dst.IP.String(), tunnel.SwIfIndex)
	} else {
		vrfIndex := p.server.networks[cn.Vni].VRF.Tables[familyIdx]
		p.log.Infof("connectivity(add) vxlan route dst=%s via swIfIndex %d in VRF %d (VNI:%d)", cn.Dst.IP.String(),
			tunnel.SwIfIndex, vrfIndex, cn.Vni)
		table = vrfIndex
	}
	route := &types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: tunnel.SwIfIndex,
			Gw:        nodeIP,
		}},
		Table: table,
	}
	_, found = p.vxlanRoutes[tunnel.SwIfIndex]
	if !found {
		p.vxlanRoutes[tunnel.SwIfIndex] = make(map[string]bool)
	}
	p.vxlanRoutes[tunnel.SwIfIndex][route.Dst.String()] = true
	return p.vpp.RouteAdd(route)
}

func (p *VXLanProvider) DelConnectivity(cn *common.NodeConnectivity) error {
	tunnel, found := p.vxlanIfs[cn.NextHop.String()+"-"+fmt.Sprint(cn.Vni)]
	if !found {
		return errors.Errorf("Deleting unknown vxlan tunnel cn=%s", cn.String())
	}
	nodeIP, err := p.getNodeIpForConnectivity(cn)
	if err != nil {
		return err
	}

	var routeToDelete *types.Route
	if cn.Vni == 0 {
		p.log.Infof("connectivity(del) VXLan cn=%s swIfIndex=%d", cn.String(), tunnel.SwIfIndex)
		routeToDelete = &types.Route{
			Dst: &cn.Dst,
			Paths: []types.RoutePath{{
				SwIfIndex: tunnel.SwIfIndex,
				Gw:        nodeIP,
			}},
		}
	} else {
		familyIdx := 0
		if vpplink.IsIP6(cn.Dst.IP) {
			familyIdx = 1
		}
		vrfIndex := p.server.networks[cn.Vni].VRF.Tables[familyIdx]
		p.log.Infof("connectivity(del) VXLan cn=%s swIfIndex=%d in VRF %d (VNI:%d)", cn.String(), tunnel.SwIfIndex, vrfIndex, cn.Vni)
		routeToDelete = &types.Route{
			Dst: &cn.Dst,
			Paths: []types.RoutePath{{
				SwIfIndex: tunnel.SwIfIndex,
				Gw:        nodeIP,
			}},
			Table: vrfIndex,
		}
	}

	err = p.vpp.RouteDel(routeToDelete)
	if err != nil {
		return errors.Wrapf(err, "Error deleting vxlan tunnel route")
	}

	delete(p.vxlanRoutes[tunnel.SwIfIndex], routeToDelete.Dst.String())

	remaining_routes, found := p.vxlanRoutes[tunnel.SwIfIndex]
	if !found || len(remaining_routes) == 0 {
		p.log.Infof("connectivity(del) all gone. Deleting VXLan tunnel swIfIndex=%d", tunnel.SwIfIndex)
		if cn.Vni == 0 {
			err = p.vpp.RouteDel(&types.Route{
				Dst: common.ToMaxLenCIDR(cn.NextHop),
				Paths: []types.RoutePath{{
					SwIfIndex: tunnel.SwIfIndex,
					Gw:        nil,
				}},
				Table: common.PodVRFIndex,
			})
			if err != nil {
				p.log.Errorf("Error deleting vxlan route dst=%s via tunnel swIfIndex=%d %s", cn.NextHop.String(), tunnel.SwIfIndex, err)
			}
		}
		err = p.vpp.DelVXLanTunnel(&tunnel)
		if err != nil {
			p.log.Errorf("Error deleting VXLan tunnel %s after error: %v", tunnel.String(), err)
		}
		delete(p.vxlanIfs, cn.NextHop.String()+"-"+fmt.Sprint(cn.Vni))
		common.SendEvent(common.CalicoVppEvent{
			Type: common.TunnelDeleted,
			Old:  tunnel.SwIfIndex,
		})
	}
	return nil
}
