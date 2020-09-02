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
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IpsecProvider struct {
	*ConnectivityProviderData
	ipsecIfs map[string][]uint32
}

func (p *IpsecProvider) OnVppRestart() {
	p.ipsecIfs = make(map[string][]uint32)
}

func (p *IpsecProvider) Init() {
}

func NewIPsecProvider(d *ConnectivityProviderData) *IpsecProvider {
	return &IpsecProvider{d, make(map[string][]uint32)}
}

func ipToSafeString(addr net.IP) string {
	return strings.ReplaceAll(strings.ReplaceAll(addr.String(), ".", "_"), ":", "_")
}

func profileName(srcNodeAddr, destNodeAddr net.IP) string {
	return "pr_" + ipToSafeString(srcNodeAddr) + "_to_" + ipToSafeString(destNodeAddr)
}

func (p IpsecProvider) setupTunnelWithIds(i int, j int, destNodeAddr net.IP, nodeIP net.IP) (err error) {
	src := net.IP(append([]byte(nil), nodeIP.To4()...))
	src[2] += byte(i)
	dst := net.IP(append([]byte(nil), destNodeAddr.To4()...))
	dst[2] += byte(j)
	p.log.Infof("ROUTING: Adding IPsec tunnel %s -> %s", src, dst)
	swIfIndex, err := p.setupOneTunnel(src, dst, config.IPSecIkev2Psk)
	if err != nil {
		return errors.Wrapf(err, "error configuring ipsec tunnel from %s to %s", src.String(), dst.String())
	}
	p.ipsecIfs[destNodeAddr.String()] = append(p.ipsecIfs[destNodeAddr.String()], swIfIndex)
	return nil
}

func (p IpsecProvider) setupTunnels(destNodeAddr net.IP) (err error) {
	/* IP6 is not yet supported by ikev2 */
	nodeIP := p.getNodeIP(false /* isv6 */)
	for i := 0; i < config.IpsecAddressCount; i++ {
		if config.CrossIpsecTunnels {
			for j := 0; j < config.IpsecAddressCount; j++ {
				err := p.setupTunnelWithIds(i, j, destNodeAddr, nodeIP)
				if err != nil {
					return err
				}
			}
		} else {
			err := p.setupTunnelWithIds(i, i, destNodeAddr, nodeIP)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p IpsecProvider) setupOneTunnel(src, dst net.IP, psk string) (tunSwIfIndex uint32, err error) {
	swIfIndex, err := p.vpp.AddIpipTunnel(src, dst, 0)
	if err != nil {
		return 0, errors.Wrapf(err, "Error adding ipip tunnel %s -> %s", src.String(), dst.String())
	}

	err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		// TODO : delete tunnel
		return 0, errors.Wrapf(err, "Error seting ipip tunnel %d unnumbered: %s", swIfIndex)
	}

	// Always enable GSO feature on IPIP tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
	err = p.vpp.EnableGSOFeature(swIfIndex)
	if err != nil {
		// TODO : delete tunnel
		return 0, errors.Wrapf(err, "Error enabling gso for ipip interface")
	}

	// Add and configure related IKE profile
	profile := profileName(src, dst)
	err = p.vpp.AddIKEv2Profile(profile)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.vpp.SetIKEv2PSKAuth(profile, psk)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.vpp.SetIKEv2LocalIDAddress(profile, src)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.vpp.SetIKEv2RemoteIDAddress(profile, dst)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.vpp.SetIKEv2PermissiveTrafficSelectors(profile)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	p.log.Infof("IKE: Profile %s = swifindex %d", profile, swIfIndex)
	err = p.vpp.SetIKEv2TunnelInterface(profile, swIfIndex)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	// Compare addresses lexicographically to select an initiator
	if bytes.Compare(src.To4(), dst.To4()) > 0 {
		p.log.Infof("IKE: Set responder %s->%s", src.String(), dst.String())
		err = p.vpp.SetIKEv2Responder(profile, config.DataInterfaceSwIfIndex, dst)
		if err != nil {
			return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
		}

		err = p.vpp.SetIKEv2DefaultTransforms(profile)
		if err != nil {
			return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
		}

		err = p.vpp.IKEv2Initiate(profile)
		if err != nil {
			return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
		}
	}

	// Wait for IPsec connection to be established to bring tunnel up
	go p.waitForIPsecSA(profile, swIfIndex)

	return swIfIndex, nil
}

func (p *IpsecProvider) waitForIPsecSA(profile string, ipipInterface uint32) {
	for {
		time.Sleep(time.Second)
		iface, err := p.vpp.GetInterfaceDetails(ipipInterface)
		if err != nil {
			p.log.Errorf("Cannot get IPIP tunnel %d status", ipipInterface)
			return
		}
		if !iface.IsUp {
			p.log.Debugf("IPIP tunnel %d still down", ipipInterface)
			continue
		}
		p.log.Debugf("Profile %s tunnel now up", profile)
		return
	}
}

func getIPSecRoutePaths(swIfIndices []uint32) []types.RoutePath {
	paths := make([]types.RoutePath, 0, len(swIfIndices))
	for _, swIfIndex := range swIfIndices {
		paths = append(paths, types.RoutePath{
			Gw:        nil,
			Table:     0,
			SwIfIndex: swIfIndex,
		})
	}
	return paths
}

func (p IpsecProvider) AddConnectivity(cn *NodeConnectivity) (err error) {
	if _, found := p.ipsecIfs[cn.NextHop.String()]; !found {
		err = p.setupTunnels(cn.NextHop)
		if err != nil {
			return errors.Wrapf(err, "Error configuring IPSEC tunnels to %s", cn.NextHop)
		}
	}
	swIfIndices := p.ipsecIfs[cn.NextHop.String()]
	p.log.Infof("IPSEC: ADD %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), swIfIndices)
	err = p.vpp.RouteAdd(&types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(swIfIndices),
	})
	if err != nil {
		return errors.Wrapf(err, "Error adding IPSEC routes to  %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), swIfIndices)
	}
	return nil
}

func (p IpsecProvider) DelConnectivity(cn *NodeConnectivity) (err error) {
	// TODO remove ike profile and teardown tunnel if there are no more routes?
	swIfIndices, found := p.ipsecIfs[cn.NextHop.String()]
	if !found {
		return errors.Errorf("Deleting unknown ipip tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("IPSEC: DEL %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), swIfIndices)
	err = p.vpp.RouteDel(&types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(swIfIndices),
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting route ipip tunnel %v: %v", swIfIndices)
	}
	return nil
}
