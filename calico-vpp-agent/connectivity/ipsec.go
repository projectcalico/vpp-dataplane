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
	"github.com/projectcalico/vpp-dataplane/config/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IpsecTunnel struct {
	*types.IPIPTunnel
	cancel func()
}

func NewIpsecTunnel(ipipTunnel *types.IPIPTunnel) *IpsecTunnel {
	return &IpsecTunnel{IPIPTunnel: ipipTunnel, cancel: func() {}}
}

func ipToSafeString(addr net.IP) string {
	return strings.ReplaceAll(strings.ReplaceAll(addr.String(), ".", "_"), ":", "_")
}

func (tunnel *IpsecTunnel) Profile() string {
	return fmt.Sprintf("pr_%s_to_%s", ipToSafeString(tunnel.Src), ipToSafeString(tunnel.Dst))
}

func (tunnel *IpsecTunnel) IsInitiator() bool {
	// Compare addresses lexicographically to select an initiator
	return bytes.Compare(tunnel.Src.To4(), tunnel.Dst.To4()) > 0
}

type IpsecProvider struct {
	*ConnectivityProviderData
	ipsecIfs         map[string][]IpsecTunnel
	ipsecRoutes      map[string]map[string]bool
	nonCryptoThreads int
}

func (p *IpsecProvider) EnableDisable(isEnable bool) {
}

func (p *IpsecProvider) Enabled(cn *common.NodeConnectivity) bool {
	return config.EnableIPSec
}

func (p *IpsecProvider) RescanState() {
	p.ipsecIfs = make(map[string][]IpsecTunnel)
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
		pmap[profile.Name] = true
	}
	ip4, ip6 := p.server.GetNodeIPs()
	for _, tunnel := range tunnels {
		if (ip4 != nil && tunnel.Src.Equal(*ip4)) || (ip6 != nil && tunnel.Src.Equal(*ip6)) {
			ipsecTunnel := NewIpsecTunnel(tunnel)
			if _, found := pmap[ipsecTunnel.Profile()]; found {
				p.ipsecIfs[ipsecTunnel.Dst.String()] = append(p.ipsecIfs[ipsecTunnel.Dst.String()], *ipsecTunnel)
			}
		}
	}

	indexTunnel := make(map[uint32]IpsecTunnel)
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

		p.log.Infof("Using async workers for ipsec, nonCryptoThreads=%d", p.nonCryptoThreads)
		// setting first p.nonCryptoThreads threads to not be used for Crypto calculation (-> other packet processing)
		// and let the remaining threads handle crypto operations
		for i := 0; i < p.nonCryptoThreads; i++ {
			err = p.vpp.SetCryptoWorker(uint32(i), false)
			if err != nil {
				p.log.Errorf("SetCryptoWorker error %s", err)
			}
		}
	}
}

func NewIPsecProvider(d *ConnectivityProviderData, nonCryptoThreads int) *IpsecProvider {
	return &IpsecProvider{
		ConnectivityProviderData: d,
		ipsecIfs:                 make(map[string][]IpsecTunnel),
		ipsecRoutes:              make(map[string]map[string]bool),
		nonCryptoThreads:         nonCryptoThreads,
	}
}

func (p *IpsecProvider) getIPSECTunnelSpecs(nodeIP4, destNodeAddr *net.IP) (tunnels []IpsecTunnel) {
	if config.CrossIpsecTunnels {
		for i := 0; i < config.IpsecAddressCount; i++ {
			for j := 0; j < config.IpsecAddressCount; j++ {
				tunnel := NewIpsecTunnel(&types.IPIPTunnel{})
				tunnel.Src = net.IP(append([]byte(nil), nodeIP4.To4()...))
				tunnel.Src[2] += byte(i)
				tunnel.Dst = net.IP(append([]byte(nil), destNodeAddr.To4()...))
				tunnel.Dst[2] += byte(j)
				tunnels = append(tunnels, *tunnel)
			}
		}
	} else {
		for i := 0; i < config.IpsecAddressCount; i++ {
			tunnel := NewIpsecTunnel(&types.IPIPTunnel{})
			tunnel.Src = net.IP(append([]byte(nil), nodeIP4.To4()...))
			tunnel.Src[2] += byte(i)
			tunnel.Dst = net.IP(append([]byte(nil), destNodeAddr.To4()...))
			tunnel.Dst[2] += byte(i)
			tunnels = append(tunnels, *tunnel)
		}
	}

	return tunnels
}

func (p *IpsecProvider) createIPSECTunnel(tunnel *IpsecTunnel, psk string, stack *vpplink.CleanupStack) error {
	swIfIndex, err := p.vpp.AddIPIPTunnel(tunnel.IPIPTunnel)
	if err != nil {
		return errors.Wrapf(err, "Error adding ipip tunnel %s", tunnel.String())
	} else {
		stack.Push(p.vpp.DelIPIPTunnel, tunnel)
	}

	common.SendEvent(common.CalicoVppEvent{
		Type: common.TunnelAdded,
		New:  swIfIndex,
	})
	stack.Push(common.SendEvent, common.CalicoVppEvent{
		Type: common.TunnelDeleted,
		Old:  swIfIndex,
	})

	err = p.vpp.InterfaceSetUnnumbered(swIfIndex, common.VppManagerInfo.GetMainSwIfIndex())
	if err != nil {
		return errors.Wrapf(err, "Error setting ipip tunnel %s unnumbered", tunnel.String())
	}

	// Always enable GSO feature on IPIP tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
	err = p.vpp.EnableGSOFeature(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error enabling gso for ipip interface")
	}

	err = p.vpp.CnatEnableFeatures(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error enabling nat for ipip interface")
	}

	p.log.Debugf("Routing pod->node %s traffic into tunnel (swIfIndex %d)", tunnel.Dst.String(), swIfIndex)
	route := &types.Route{
		Dst: common.ToMaxLenCIDR(tunnel.Dst),
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
		Table: common.PodVRFIndex,
	}
	err = p.vpp.RouteAdd(route)
	if err != nil {
		return errors.Wrapf(err, "Error adding route to %s in ipip tunnel %d for pods", tunnel.Dst.String(), swIfIndex)
	} else {
		stack.Push(p.vpp.RouteDel, route)
	}

	// Add and configure related IKE profile
	err = p.vpp.AddIKEv2Profile(tunnel.Profile())
	if err != nil {
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	} else {
		stack.Push(p.vpp.DelIKEv2Profile, tunnel.Profile())
	}

	p.log.Infof("connectivity(add) IKE Profile=%s swIfIndex=%d", tunnel.Profile(), tunnel.SwIfIndex)
	err = p.vpp.SetIKEv2TunnelInterface(tunnel.Profile(), swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2PSKAuth(tunnel.Profile(), psk)
	if err != nil {
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2LocalIDAddress(tunnel.Profile(), tunnel.Src)
	if err != nil {
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2RemoteIDAddress(tunnel.Profile(), tunnel.Dst)
	if err != nil {
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	err = p.vpp.SetIKEv2PermissiveTrafficSelectors(tunnel.Profile())
	if err != nil {
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	// Compare addresses lexicographically to select an initiator
	if tunnel.IsInitiator() {
		p.log.Infof("connectivity(add) IKE Set responder=%s", tunnel.String())
		err = p.vpp.SetIKEv2Responder(tunnel.Profile(), common.VppManagerInfo.GetMainSwIfIndex(), tunnel.Dst)
		if err != nil {
			return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
		}

		err = p.vpp.SetIKEv2DefaultTransforms(tunnel.Profile())
		if err != nil {
			return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
		}

		err = p.vpp.IKEv2Initiate(tunnel.Profile())
		if err != nil {
			return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
		}
	}
	p.log.Infof("connectivity(add) IPsec tunnel=%s", tunnel.String())

	// Wait for IPsec connection to be established to bring tunnel up
	tunnel.cancel = p.waitForIPsecSA(*tunnel)

	return nil
}

func (p *IpsecProvider) waitForIPsecSA(tunnel IpsecTunnel) func() {
	ticker := time.NewTicker(time.Second)
	done := make(chan bool)

	go (func() {
		defer ticker.Stop()
		for {
			select {
			case <-done:
				p.log.Infof("connectivity(del) canceling Profile=%s", tunnel.Profile())
				return
			case <-ticker.C:
				iface, err := p.vpp.GetInterfaceDetails(tunnel.SwIfIndex)
				if err != nil {
					p.log.WithError(err).Errorf("Cannot get IPIP tunnel %s status", tunnel.String())
					return
				}
				if iface.IsUp {
					p.log.Infof("connectivity(add) tunnel now up Profile=%s", tunnel.Profile())
					return
				}

				if tunnel.IsInitiator() {
					p.log.Warnf("IPIP tunnel still down, re-trying initiate IKE for IPsec tunnel=%s", tunnel.String())
					err = p.vpp.IKEv2Initiate(tunnel.Profile())
					if err != nil {
						p.log.Errorf("error configuring IPsec tunnel %s %s", tunnel.String(), err)
					}
				}
			}
		}
	})()
	return func() { done <- true }
}

func getIPSecRoutePaths(tunnels []IpsecTunnel) []types.RoutePath {
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
	var route *types.Route
	var tunnels []IpsecTunnel

	cn.NextHop, err = p.forceOtherNodeIp4(cn.NextHop)
	if err != nil {
		return errors.Wrap(err, "Ipsec v6 config failed")
	}
	/* IP6 is not yet supported by ikev2 */
	nodeIP4, _ := p.server.GetNodeIPs()
	if nodeIP4 == nil {
		return fmt.Errorf("no ip4 node address found")
	}

	stack := p.vpp.NewCleanupStack()

	_, found := p.ipsecIfs[cn.NextHop.String()]
	if !found {
		tunnelSpecs := p.getIPSECTunnelSpecs(nodeIP4, &cn.NextHop)
		for _, tunnelSpec := range tunnelSpecs {
			err = p.createIPSECTunnel(&tunnelSpec, config.IPSecIkev2Psk, stack)
			if err != nil {
				err = errors.Wrapf(err, "Error configuring IPSEC tunnels to %s", cn.NextHop)
				goto err
			}
			p.ipsecIfs[cn.NextHop.String()] = append(p.ipsecIfs[cn.NextHop.String()], tunnelSpec)
		}
	}
	tunnels = p.ipsecIfs[cn.NextHop.String()]
	p.log.Infof("connectivity(add) IPSEC cn=%s tunnels=%v", cn.String(), tunnels)
	route = &types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(tunnels),
	}
	err = p.vpp.RouteAdd(route)
	if err != nil {
		err = errors.Wrapf(err, "Error adding IPSEC routes to %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), tunnels)
		goto err
	} else {
		stack.Push(p.vpp.RouteDel, route)
	}
	_, found = p.ipsecRoutes[cn.NextHop.String()]
	if !found {
		p.ipsecRoutes[cn.NextHop.String()] = make(map[string]bool)
	}
	p.ipsecRoutes[cn.NextHop.String()][route.Dst.String()] = true

	return nil

err:
	p.log.Errorf("Error, try a cleanup %+v", err)
	stack.Execute()
	return err
}

func (p *IpsecProvider) DelConnectivity(cn *common.NodeConnectivity) (err error) {
	cn.NextHop, err = p.forceOtherNodeIp4(cn.NextHop)
	if err != nil {
		return errors.Wrap(err, "Ipsec v6 config failed")
	}

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
		p.log.Errorf("Error deleting route ipip tunnel %v: %v", tunnels, err)
	}

	delete(p.ipsecRoutes[cn.NextHop.String()], routeToDelete.Dst.String())

	remaining_routes, found := p.ipsecRoutes[cn.NextHop.String()]
	if !found || len(remaining_routes) == 0 {
		for _, tunnel := range tunnels {
			tunnel.cancel()
			p.vpp.DelIKEv2Profile(tunnel.Profile())
			p.log.Infof("connectivity(del) Deleting IPsec tunnel=%s", tunnel)
			err := p.vpp.DelIPIPTunnel(tunnel.IPIPTunnel)
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
