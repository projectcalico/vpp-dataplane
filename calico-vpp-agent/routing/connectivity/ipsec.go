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
	commonAgent "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IpsecProvider struct {
	*ConnectivityProviderData
	ipsecIfs map[string][]*types.IPIPTunnel
}

func (p *IpsecProvider) OnVppRestart() {

	var nbDataThread int = 0
	numVPPWorkers, err := p.vpp.GetNumVPPWorkers()
	if err != nil {
		p.log.Errorf("GetNumVPPWorkers error %s", err)
	}

	if config.IpsecNbAsyncCryptoThread > 0 {
		var err error
		err = p.vpp.SetIPsecAsyncMode(true)
		if err != nil {
			p.log.Errorf("SetIPsecAsyncMode error %s", err)
		}

		nbDataThread = (int)(numVPPWorkers) - config.IpsecNbAsyncCryptoThread
		p.log.Infof("nbDataThread %d", nbDataThread)

		for i := 0; i < nbDataThread; i++ {
			err = p.vpp.SetCryptoWorker(uint32(i), false)
			if err != nil {
				p.log.Errorf("SetCryptoWorker error %s", err)
			}
		}
	}
	p.ipsecIfs = make(map[string][]*types.IPIPTunnel)
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
	nodeIP4 := p.server.GetNodeIP(false)
	nodeIP6 := p.server.GetNodeIP(true)
	for _, tunnel := range tunnels {
		if tunnel.Src.Equal(nodeIP4) || tunnel.Src.Equal(nodeIP6) {
			_, found := pmap[profileName(tunnel)]
			if found {
				p.ipsecIfs[tunnel.Dst.String()] = append(p.ipsecIfs[tunnel.Dst.String()], tunnel)
			}
		}
	}
}

func NewIPsecProvider(d *ConnectivityProviderData) *IpsecProvider {
	return &IpsecProvider{d, make(map[string][]*types.IPIPTunnel)}
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
	nodeIP := p.server.GetNodeIP(false /* isv6 */)
	for i := 0; i < config.IpsecAddressCount; i++ {
		if config.CrossIpsecTunnels {
			for j := 0; j < config.IpsecAddressCount; j++ {
				err := p.createOneIndexedIPSECTunnel(i, j, destNodeAddr, nodeIP)
				if err != nil {
					return err
				}
			}
		} else {
			err := p.createOneIndexedIPSECTunnel(i, i, destNodeAddr, nodeIP)
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
	p.log.Infof("ROUTING: Adding IPsec tunnel %s", tunnel.String())
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

	err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		p.errorCleanup(tunnel, "")
		return errors.Wrapf(err, "Error seting ipip tunnel %s unnumbered: %s", tunnel.String())
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
		Dst: commonAgent.ToMaxLenCIDR(tunnel.Dst),
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
		Table: commonAgent.PodVRFIndex,
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

	p.log.Infof("IKE: Profile %s = swifindex %d", profile, tunnel.SwIfIndex)
	err = p.vpp.SetIKEv2TunnelInterface(profile, swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel, profile)
		return errors.Wrapf(err, "error configuring IPsec tunnel %s", tunnel.String())
	}

	// Compare addresses lexicographically to select an initiator
	if bytes.Compare(tunnel.Src.To4(), tunnel.Dst.To4()) > 0 {
		p.log.Infof("IKE: Set responder %s", tunnel.String())
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
			p.log.Infof("Profile %s tunnel now up", profile)
			return
		}

		if bytes.Compare(tunnel.Src.To4(), tunnel.Dst.To4()) > 0 {
			p.log.Infof("IPIP tunnel %s still down, re-trying initiate", tunnel.String())
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
	p.log.Infof("IPSEC: ADD %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), tunnels)
	err = p.vpp.RouteAdd(&types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(tunnels),
	})
	if err != nil {
		return errors.Wrapf(err, "Error adding IPSEC routes to  %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), tunnels)
	}
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
	p.log.Infof("IPSEC: DEL %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), tunnels)
	err = p.vpp.RouteDel(&types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(tunnels),
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting route ipip tunnel %v: %v", tunnels)
	}
	return nil
}
