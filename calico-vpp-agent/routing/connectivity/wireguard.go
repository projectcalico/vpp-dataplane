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
	"context"
	"encoding/base64"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type WireguardProvider struct {
	*ConnectivityProviderData
	wireguardTunnel *types.WireguardTunnel
	wireguardPeers  map[string]types.WireguardPeer
}

func NewWireguardProvider(d *ConnectivityProviderData) *WireguardProvider {
	return &WireguardProvider{d, nil, make(map[string]types.WireguardPeer)}
}

func (p *WireguardProvider) Enabled() bool {
	felixConf := p.server.GetFelixConfig()
	if felixConf == nil {
		return false
	}
	if felixConf.WireguardEnabled == nil {
		return false
	}
	return *felixConf.WireguardEnabled
}

func (p *WireguardProvider) getWireguardPort() uint16 {
	felixConf := p.server.GetFelixConfig()
	if felixConf == nil {
		return uint16(config.DefaultWireguardPort)
	}
	if felixConf.WireguardListeningPort == nil {
		return uint16(config.DefaultWireguardPort)
	}
	return uint16(*felixConf.WireguardListeningPort)
}

func (p *WireguardProvider) OnVppRestart() {
	p.wireguardPeers = make(map[string]types.WireguardPeer)
	p.wireguardTunnel = nil
}

func (p *WireguardProvider) getNodePublicKey(cn *NodeConnectivity) ([]byte, error) {
	p.log.Infof("Wireguard: pkey ?")
	node := p.server.GetNodeByIp(cn.NextHop)
	p.log.Infof("Wireguard: pkey %s = %s", node.Name, node.Status.WireguardPublicKey)
	key, err := base64.StdEncoding.DecodeString(node.Status.WireguardPublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Error decoding wireguard public key %s", node.Status.WireguardPublicKey)
	}
	return key, nil
}

func (p *WireguardProvider) publishWireguardPublicKey(pubKey string) error {
	// Ref: felix/daemon/daemon.go:1056
	node, err := p.server.Clientv3().Nodes().Get(context.Background(), config.NodeName, options.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Error getting node config")
	}
	p.log.Infof("Wireguard: publishing pkey %s=%s", config.NodeName, pubKey)
	node.Status.WireguardPublicKey = pubKey
	_, err = p.server.Clientv3().Nodes().Update(context.Background(), node, options.SetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Error updating node config")
	}
	return nil
}

func (p *WireguardProvider) TunnelIsIP6() bool {
	if p.wireguardTunnel == nil {
		return false
	}
	return vpplink.IsIP6(p.wireguardTunnel.Addr)
}

func (p *WireguardProvider) RescanState() {
	nodeIP4 := p.server.GetNodeIP(false)
	nodeIP6 := p.server.GetNodeIP(true)

	p.wireguardPeers = make(map[string]types.WireguardPeer)
	p.wireguardTunnel = nil

	p.log.Debugf("Wireguard: Rescanning existing tunnels")
	tunnels, err := p.vpp.ListWireguardTunnels()
	if err != nil {
		p.log.Errorf("Error listing wireguard tunnels: %v", err)
	}
	for _, tunnel := range tunnels {
		if tunnel.Addr.Equal(nodeIP4) || tunnel.Addr.Equal(nodeIP6) {
			p.log.Infof("Found existing tunnel: %s", tunnel)
			p.wireguardTunnel = tunnel
			break
		}
	}

	p.log.Debugf("Wireguard: Rescanning existing peers")
	peers, err := p.vpp.ListWireguardPeers()
	if err != nil {
		p.log.Errorf("Error listing wireguard peers: %v", err)
	}

	for _, peer := range peers {
		p.wireguardPeers[peer.Addr.String()] = *peer
	}
}

func (p *WireguardProvider) errorCleanup(tunnel *types.WireguardTunnel) {
	err := p.vpp.DelWireguardTunnel(tunnel)
	if err != nil {
		p.log.Errorf("Error deleting wireguard tunnel %s after error: %v", tunnel.String(), err)
	}
}

func (p *WireguardProvider) createWireguardTunnel(isv6 bool) error {
	nodeIp := p.server.GetNodeIP(isv6)
	if nodeIp == nil {
		p.log.Infof("Wireguard: didnt find nodeIP for v6=%t", isv6)
		return nil
	}

	p.log.Debugf("Adding wireguard Tunnel to VPP")
	tunnel := &types.WireguardTunnel{
		Addr: nodeIp,
		Port: p.getWireguardPort(),
	}
	swIfIndex, err := p.vpp.AddWireguardTunnel(tunnel)
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error creating wireguard tunnel")
	}
	// fetch public key of created tunnel
	createdTunnel, err := p.vpp.GetWireguardTunnel(swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error fetching wireguard tunnel after creation")
	}
	tunnel.PublicKey = createdTunnel.PublicKey

	err = p.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error seting wireguard tunnel unnumbered")
	}

	err = p.vpp.EnableGSOFeature(swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error enabling gso for wireguard interface")
	}

	err = p.vpp.CnatEnableFeatures(swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error enabling nat for wireguard interface")
	}

	err = p.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error setting wireguard interface up")
	}

	key := base64.StdEncoding.EncodeToString(tunnel.PublicKey)
	err = p.publishWireguardPublicKey(key)
	if err != nil {
		return errors.Wrapf(err, "Wireguard: publish PublicKey error")
	}
	p.wireguardTunnel = tunnel
	p.log.Infof("Wireguard: Added %s", p.wireguardTunnel)
	return nil
}

func (p *WireguardProvider) AddConnectivity(cn *NodeConnectivity) error {
	if p.wireguardTunnel == nil {
		p.log.Infof("Wireguard: Creating tunnel")
		nodeIP4 := p.server.GetNodeIP(false)
		if nodeIP4 == nil {
			return errors.Errorf("Wireguard: no IP4 found for node")
		}
		err := p.createWireguardTunnel(nodeIP4 == nil /* isv6 */)
		if err != nil {
			return errors.Wrapf(err, "Wireguard: Error creating tunnel")
		}
	}
	if p.TunnelIsIP6() != vpplink.IsIP6(cn.NextHop) {
		return errors.Errorf("IP46 wireguard tunnelling not supported")
	}

	key, err := p.getNodePublicKey(cn)
	if err != nil {
		return errors.Wrapf(err, "Error Getting node %s publicKey", cn.NextHop)
	}
	peer := &types.WireguardPeer{
		PublicKey:  key,
		Port:       p.getWireguardPort(),
		Addr:       cn.NextHop,
		SwIfIndex:  p.wireguardTunnel.SwIfIndex,
		AllowedIps: []net.IPNet{cn.Dst},
	}
	existingPeer, found := p.wireguardPeers[cn.NextHop.String()]
	p.log.Infof("Wireguard: NH:%s Dst:%s found:%t", cn.NextHop, cn.Dst, found)
	if found {
		peer.AllowedIps = existingPeer.AllowedIps
		peer.AddAllowedIp(cn.Dst)
		/* Only update if we need to */
		if !existingPeer.Equal(peer) {
			p.log.Infof("Wireguard: Delete (update) peer [%s]", existingPeer.String())
			err := p.vpp.DelWireguardPeer(&existingPeer)
			if err != nil {
				return errors.Wrapf(err, "Error deleting (update) wireguard peer %s", existingPeer.String())
			}
			p.log.Infof("Wireguard: Addback (update) peer [%s]", peer)
			_, err = p.vpp.AddWireguardPeer(peer)
			if err != nil {
				return errors.Wrapf(err, "Error adding (update) wireguard peer %s", peer)
			}
		}
	} else {
		p.log.Infof("Wireguard: Add peer [%s]", peer)
		_, err := p.vpp.AddWireguardPeer(peer)
		if err != nil {
			return errors.Wrapf(err, "Error adding wireguard peer [%s]", peer)
		}
	}
	p.log.Infof("Wireguard: peer %s ok", peer)
	p.wireguardPeers[cn.NextHop.String()] = *peer

	p.log.Debugf("Adding wireguard tunnel route to %s via swIfIndex %d", cn.Dst.IP, p.wireguardTunnel.SwIfIndex)
	err = p.vpp.RouteAdd(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: p.wireguardTunnel.SwIfIndex,
			Gw:        nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error Adding route to wireguard tunnel")
	}
	return nil
}

func (p *WireguardProvider) DelConnectivity(cn *NodeConnectivity) error {
	peer, found := p.wireguardPeers[cn.NextHop.String()]
	if !found {
		p.log.Infof("Wireguard: Del unknown %s", cn.NextHop.String())
		return errors.Errorf("Deleting unknown wireguard tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("Wireguard: Del ?->%s %d", cn.NextHop.String(), peer.Index)
	peer.DelAllowedIp(cn.Dst)
	err := p.vpp.DelWireguardPeer(&peer)
	if err != nil {
		return errors.Wrapf(err, "Error deleting wireguard peer %s", peer)
	}
	delete(p.wireguardPeers, cn.NextHop.String())
	if len(peer.AllowedIps) != 0 {
		if err != nil {
			return errors.Wrapf(err, "Error adding (back) wireguard peer %s", peer)
		}
		p.wireguardPeers[cn.NextHop.String()] = peer
	}
	err = p.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: peer.SwIfIndex,
			Gw:        nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting wireguard tunnel route")
	}
	// We don't delete the interface so keep it in the map
	// p.wireguardTunnel
	return nil
}
