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
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IpsecProvider struct {
	*ConnectivityProviderData
	ipsecIfs     map[string][]*types.IPIPTunnel
	ipsecRoutes  map[string]map[string]bool
	nDataThreads int
}

func (p *IpsecProvider) Enabled() bool {
	return config.EnableIPSec
}

func (p *IpsecProvider) RescanState() {
	p.ipsecIfs = make(map[string][]*types.IPIPTunnel)
	tunnels, err := p.vpp.ListIPIPTunnels()
	if err != nil {
		p.log.Errorf("Error listing ipip tunnels: %v", err)
	}
	pmap := make(map[string]bool)
	profiles, err := p.vpp.ListIKEv2Profiles()
	if err != nil {
		p.log.Errorf("Error listing ikev2 profiles: %v", err)
	}
	for _, profile := range profiles {
		pmap[profile] = true
	}
	ip4, ip6 := p.server.GetNodeIPs()
	for _, tunnel := range tunnels {
		if (ip4 != nil && tunnel.Src.Equal(*ip4)) || (ip6 != nil && tunnel.Src.Equal(*ip6)) {
			_, found := pmap[profileName(tunnel)]
			if found {
				p.ipsecIfs[tunnel.Dst.String()] = append(p.ipsecIfs[tunnel.Dst.String()], tunnel)
			}
		}
	}

	indexTunnel := make(map[uint32]*types.IPIPTunnel)
	for _, tunnels := range p.ipsecIfs {
		for _, tunnel := range tunnels {
			indexTunnel[tunnel.SwIfIndex] = tunnel
		}
	}

	p.ipsecRoutes = make(map[string]map[string]bool)
	routes, err := p.vpp.GetRoutes(0, false)
	if err != nil {
		p.log.Errorf("Error listing routes: %v", err)
	}
	for _, route := range routes {
		for _, routePath := range route.Paths {
			tunnel, exists := indexTunnel[routePath.SwIfIndex]
			if exists {
				_, found := p.ipsecRoutes[tunnel.Dst.String()]
				if !found {
					p.ipsecRoutes[tunnel.Dst.String()] = make(map[string]bool)
				}
				p.ipsecRoutes[tunnel.Dst.String()][route.Dst.String()] = true
			}
		}
	}

	if config.IpsecNbAsyncCryptoThread > 0 {
		err := p.vpp.SetIPsecAsyncMode(true)
		if err != nil {
			p.log.Errorf("SetIPsecAsyncMode error %s", err)
		}

		p.log.Infof("Using async workers for ipsec, nbDataThread=%d", p.nDataThreads)
		for i := 0; i < p.nDataThreads; i++ {
			err = p.vpp.SetCryptoWorker(uint32(i), false)
			if err != nil {
				p.log.Errorf("SetCryptoWorker error %s", err)
			}
		}
	}
}

func NewIPsecProvider(d *ConnectivityProviderData, nDataThreads int) *IpsecProvider {
	return &IpsecProvider{
		ConnectivityProviderData: d,
		ipsecIfs:                 make(map[string][]*types.IPIPTunnel),
		ipsecRoutes:              make(map[string]map[string]bool),
		nDataThreads:             nDataThreads,
	}
}

func ipToSafeString(addr net.IP) string {
	return strings.ReplaceAll(strings.ReplaceAll(addr.String(), ".", "_"), ":", "_")
}

func profileName(tunnel *types.IPIPTunnel) string {
	return fmt.Sprintf("pr_%s_to_%s", ipToSafeString(tunnel.Src), ipToSafeString(tunnel.Dst))
}

func (p *IpsecProvider) errorCleanup(tunnel *types.IPIPTunnel, profile string) {
	err := p.vpp.DelIPIPTunnel(tunnel)
	if err != nil {
		p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
	}
	if profile != "" {
		err = p.vpp.DelIKEv2Profile(profile)
		if err != nil {
			p.log.Errorf("Error deleting ipip tunnel %s after error: %v", profile, err)
		}
	}
}

func (p *IpsecProvider) createIPSECTunnels(destNodeAddr net.IP) (err error) {
	/* IP6 is not yet supported by ikev2 */
	ip4, _ := p.server.GetNodeIPs()
	if ip4 == nil {
		return fmt.Errorf("no ip4 node address found")
	}
	for i := 0; i < config.IpsecAddressCount; i++ {
		if config.CrossIpsecTunnels {
			for j := 0; j < config.IpsecAddressCount; j++ {
				err := p.createOneIndexedIPSECTunnel(i, j, destNodeAddr, *ip4)
				if err != nil {
					return err
				}
			}
		} else {
			err := p.createOneIndexedIPSECTunnel(i, i, destNodeAddr, *ip4)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *IpsecProvider) createOneIndexedIPSECTunnel(i int, j int, destNodeAddr net.IP, nodeIP net.IP) (err error) {
	src := net.IP(append([]byte(nil), nodeIP.To4()...))
	src[2] += byte(i)
	dst := net.IP(append([]byte(nil), destNodeAddr.To4()...))
	dst[2] += byte(j)

	tunnel := &types.IPIPTunnel{
		Src: src,
		Dst: dst,
	}
	p.log.Infof("connectiviy(add) IPsec tunnel=%s", tunnel.String())
	err = p.createOneIPSECTunnel(tunnel, config.IPSecIkev2Psk)
	if err != nil {
		return errors.Wrapf(err, "error configuring ipsec tunnel %s", tunnel.String())
	}
	p.ipsecIfs[destNodeAddr.String()] = append(p.ipsecIfs[destNodeAddr.String()], tunnel)
	return nil
}

func (p *IpsecProvider) createOneIPSECTunnel(tunnel *types.IPIPTunnel, psk string) error {
	swIfIndex, err := p.vpp.AddIPIPTunnel(tunnel)
	if err != nil {
		return errors.Wrapf(err, "Error adding ipip tunnel %s", tunnel.String())
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.TunnelAdded,
		New:  swIfIndex,
	})
	err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		p.errorCleanup(tunnel, "")
		return errors.Wrapf(err, "Error setting ipip tunnel %s unnumbered: %s", tunnel.String())
	}

	// Always enable GSO feature on IPIP tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
	err = p.vpp.EnableGSOFeature(swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel, "")
		return errors.Wrapf(err, "Error enabling gso for ipip interface")
	}

	err = p.vpp.CnatEnableFeatures(swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel, "")
		return errors.Wrapf(err, "Error enabling nat for ipip interface")
	}

	p.log.Debugf("Routing pod->node %s traffic into tunnel (swIfIndex %d)", tunnel.Dst.String(), swIfIndex)
	err = p.vpp.RouteAdd(&types.Route{
		Dst: common.ToMaxLenCIDR(tunnel.Dst),
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
		Table: common.PodVRFIndex,
	})
	if err != nil {
		p.errorCleanup(tunnel, "")
		return errors.Wrapf(err, "Error adding route to %s in ipip tunnel %d for pods", tunnel.Dst.String(), swIfIndex)
	}

	// Add and configure related IKE profile
	profile := profileName(tunnel)
	err = p.vpp.AddIKEv2Profile(profile)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2PSKAuth(profile, psk)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2LocalIDAddress(profile, tunnel.Src)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2RemoteIDAddress(profile, tunnel.Dst)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2PermissiveTrafficSelectors(profile)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	p.log.Infof("connectivity(add) IKE Profile=%s swIfIndex=%d", profile, tunnel.SwIfIndex)
	err = p.vpp.SetIKEv2TunnelInterface(profile, swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	// Compare addresses lexicographically to select an initiator
	if bytes.Compare(tunnel.Src.To4(), tunnel.Dst.To4()) > 0 {
		p.log.Infof("connectivity(add) IKE Set responder=%s", tunnel.String())
		err = p.vpp.SetIKEv2Responder(profile, config.DataInterfaceSwIfIndex, tunnel.Dst)
		if err != nil {
			p.errorCleanup(tunnel, profile)
			return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
		}

		err = p.vpp.SetIKEv2DefaultTransforms(profile)
		if err != nil {
			p.errorCleanup(tunnel, profile)
			return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
		}

		err = p.vpp.IKEv2Initiate(profile)
		if err != nil {
			p.errorCleanup(tunnel, profile)
			return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
		}
	}

	// Wait for IPsec connection to be established to bring tunnel up
	go p.waitForIPsecSA(profile, tunnel)

	return nil
}

func (p *IpsecProvider) waitForIPsecSA(profile string, tunnel *types.IPIPTunnel) {
	for {
		time.Sleep(time.Second)
		iface, err := p.vpp.GetInterfaceDetails(tunnel.SwIfIndex)
		if err != nil {
			p.log.Errorf("Cannot get IPIP tunnel %s status", tunnel.String())
			return
		}
		if iface.IsUp {
			p.log.Infof("connectivity(add) tunnel now up Profile=%s", profile)
			return
		}

		if bytes.Compare(tunnel.Src.To4(), tunnel.Dst.To4()) > 0 {
			p.log.Warnf("IPIP tunnel still down, re-trying initiate IKE for IPsec tunnel=%s", tunnel.String())
			err = p.vpp.IKEv2Initiate(profile)
			if err != nil {
				p.errorCleanup(tunnel, profile)
				p.log.Errorf("error configuring IPsec tunnel %s %s", tunnel.String(), err)
			}
		}
	}
}

func getIPSecRoutePaths(tunnels []*types.IPIPTunnel) []types.RoutePath {
	paths := make([]types.RoutePath, 0, len(tunnels))
	for _, tunnel := range tunnels {
		paths = append(paths, types.RoutePath{
			Gw:        nil,
			Table:     0,
			SwIfIndex: tunnel.SwIfIndex,
		})
	}
	return paths
}

func (p *IpsecProvider) forceOtherNodeIp4(addr net.IP) (ip4 net.IP, err error) {
	/* If only IP6 (e.g. ipsec) is supported, find nodeip4 out of nodeip6 */
	if !vpplink.IsIP6(addr) {
		return addr, nil
	}
	otherNode := p.GetNodeByIp(addr)
	if otherNode == nil {
		return nil, fmt.Errorf("Didnt find an ip4 for ip %s", addr.String())
	}
	nodeIP, _, err := net.ParseCIDR(otherNode.Spec.BGP.IPv4Address)
	if err != nil {
		return nil, errors.Wrapf(err, "Didnt find an ip4 for ip %s", addr.String())
	}
	return nodeIP, nil
}

func (p *IpsecProvider) AddConnectivity(cn *common.NodeConnectivity) (err error) {
	cn.NextHop, err = p.forceOtherNodeIp4(cn.NextHop)
	if err != nil {
		return errors.Wrap(err, "Ipsec v6 config failed")
	}

	if _, found := p.ipsecIfs[cn.NextHop.String()]; !found {
		err = p.createIPSECTunnels(cn.NextHop)
		if err != nil {
			return errors.Wrapf(err, "Error configuring IPSEC tunnels to %s", cn.NextHop)
		}
	}
	tunnels := p.ipsecIfs[cn.NextHop.String()]
	p.log.Infof("connectivity(add) IPSEC cn=%s tunnels=[%v]", cn.String(), tunnels)
	route := &types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(tunnels),
	}
	err = p.vpp.RouteAdd(route)
	if err != nil {
		return errors.Wrapf(err, "Error adding IPSEC routes to  %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), tunnels)
	}
	_, found := p.ipsecRoutes[cn.NextHop.String()]
	if !found {
		p.ipsecRoutes[cn.NextHop.String()] = make(map[string]bool)
	}
	p.ipsecRoutes[cn.NextHop.String()][route.Dst.String()] = true

	return nil
}

func (p *IpsecProvider) DelConnectivity(cn *common.NodeConnectivity) (err error) {
	cn.NextHop, err = p.forceOtherNodeIp4(cn.NextHop)
	if err != nil {
		return errors.Wrap(err, "Ipsec v6 config failed")
	}

	// TODO remove ike profile and teardown tunnel if there are no more routes?
	tunnels, found := p.ipsecIfs[cn.NextHop.String()]
	if !found {
		return errors.Errorf("Deleting unknown ipip tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("connectivity(del) IPSEC cn=%s tunnels=[%v]", cn.String(), tunnels)
	routeToDelete := &types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(tunnels),
	}
	err = p.vpp.RouteDel(routeToDelete)
	if err != nil {
		return errors.Wrapf(err, "Error deleting route ipip tunnel %v: %v", tunnels)
	}

	delete(p.ipsecRoutes[cn.NextHop.String()], routeToDelete.Dst.String())

	remaining_routes, found := p.ipsecRoutes[cn.NextHop.String()]
	if !found || len(remaining_routes) == 0 {
		for _, tunnel := range tunnels {
			profile := profileName(tunnel)
			p.log.Infof("connectivity(del) Deleting IKE profile=%s", profile)
			p.vpp.DelIKEv2Profile(profile)
			p.log.Infof("connectivity(del) Deleting IPsec tunnel=%s", tunnel)
			err := p.vpp.DelIPIPTunnel(tunnel)
			if err != nil {
				p.log.Errorf("Error deleting ipip tunnel %s after error: %v", tunnel.String(), err)
			}
			common.SendEvent(common.CalicoVppEvent{
				Type: common.TunnelDeleted,
				Old:  tunnel.SwIfIndex,
			})
		}
		delete(p.ipsecIfs, cn.NextHop.String())
	}
	return nil
}
