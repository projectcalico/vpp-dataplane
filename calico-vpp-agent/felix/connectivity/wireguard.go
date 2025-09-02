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
	"fmt"
	"net"

	vpptypes "github.com/calico-vpp/vpplink/api/v0"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type WireguardProvider struct {
	vpp                *vpplink.VppLink
	log                *logrus.Entry
	cache              *cache.Cache
	clientv3           calicov3cli.Interface
	wireguardTunnels   map[string]*vpptypes.WireguardTunnel
	wireguardPeers     map[string]vpptypes.WireguardPeer
	NodesToWGPublicKey map[string]string
}

func NewWireguardProvider(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, cache *cache.Cache, log *logrus.Entry) *WireguardProvider {
	return &WireguardProvider{
		vpp:                vpp,
		log:                log,
		cache:              cache,
		clientv3:           clientv3,
		wireguardTunnels:   make(map[string]*vpptypes.WireguardTunnel),
		wireguardPeers:     make(map[string]vpptypes.WireguardPeer),
		NodesToWGPublicKey: make(map[string]string),
	}
}

func (p *WireguardProvider) Enabled(cn *common.NodeConnectivity) bool {
	felixConfig := p.cache.FelixConfig
	if !felixConfig.WireguardEnabled {
		return false
	}
	if node, found := p.cache.NodeByAddr[cn.NextHop.String()]; found {
		return p.NodesToWGPublicKey[node.Name] != ""
	}
	return false
}

func (p *WireguardProvider) getWireguardPort() uint16 {
	felixConfig := p.cache.FelixConfig
	if felixConfig.WireguardListeningPort == 0 {
		return uint16(config.DefaultWireguardPort)
	}
	return uint16(felixConfig.WireguardListeningPort)
}

func (p *WireguardProvider) getNodePublicKey(cn *common.NodeConnectivity) ([]byte, error) {
	node, found := p.cache.NodeByAddr[cn.NextHop.String()]
	if !found {
		return nil, fmt.Errorf("node=%s not found", cn.NextHop.String())
	}
	if p.NodesToWGPublicKey[node.Name] == "" {
		return nil, fmt.Errorf("no public key for node=%s", node.Name)
	}

	p.log.Infof("connectivity(add) Wireguard nodeName=%s pubKey=%s", node.Name, p.NodesToWGPublicKey[node.Name])
	key, err := base64.StdEncoding.DecodeString(p.NodesToWGPublicKey[node.Name])
	if err != nil {
		return nil, errors.Wrapf(err, "Error decoding wireguard public key %s", p.NodesToWGPublicKey[node.Name])
	}
	return key, nil
}

func (p *WireguardProvider) publishWireguardPublicKey(pubKey string) error {
	// Ref: felix/daemon/daemon.go:1056
	node, err := p.clientv3.Nodes().Get(context.Background(), *config.NodeName, options.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Error getting node config")
	}
	p.log.Infof("connectivity(add) Wireguard publishing nodeName=%s pubKey=%s", *config.NodeName, pubKey)
	node.Status.WireguardPublicKey = pubKey
	_, err = p.clientv3.Nodes().Update(context.Background(), node, options.SetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Error updating node config")
	}
	return nil
}

func (p *WireguardProvider) RescanState() {
	p.wireguardPeers = make(map[string]vpptypes.WireguardPeer)
	p.wireguardTunnels = make(map[string]*vpptypes.WireguardTunnel)

	p.log.Debugf("Wireguard: Rescanning existing tunnels")
	tunnels, err := p.vpp.ListWireguardTunnels()
	if err != nil {
		p.log.Errorf("Error listing wireguard tunnels: %v", err)
	}
	for _, tunnel := range tunnels {
		if p.cache.GetNodeIP4() != nil && tunnel.Addr.Equal(*p.cache.GetNodeIP4()) {
			p.log.Infof("Found existing v4 tunnel: %s", tunnel)
			p.wireguardTunnels["ip4"] = tunnel
		}
		if p.cache.GetNodeIP6() != nil && tunnel.Addr.Equal(*p.cache.GetNodeIP6()) {
			p.log.Infof("Found existing v6 tunnel: %s", tunnel)
			p.wireguardTunnels["ip6"] = tunnel
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

func (p *WireguardProvider) errorCleanup(tunnel *vpptypes.WireguardTunnel) {
	err := p.vpp.DelWireguardTunnel(tunnel)
	if err != nil {
		p.log.Errorf("Error deleting wireguard tunnel %s after error: %v", tunnel.String(), err)
	}
}

func (p *WireguardProvider) EnableDisable(isEnable bool) {
	if isEnable {
		if len(p.wireguardTunnels) == 0 {
			err := p.createWireguardTunnels(p.cache.GetNodeIP4(), "ip4")
			if err != nil {
				p.log.Errorf("Wireguard: Error creating v4 tunnel %s", err)
				return
			}
			err = p.createWireguardTunnels(p.cache.GetNodeIP6(), "ip6")
			if err != nil {
				p.log.Errorf("Wireguard: Error creating v6 tunnel %s", err)
				return
			}
		}

		for _, tun := range p.wireguardTunnels {
			key := base64.StdEncoding.EncodeToString(tun.PublicKey)
			err := p.publishWireguardPublicKey(key)
			if err != nil {
				p.log.Errorf("Wireguard: publish PublicKey error %s", err)
			}
			// should be the same for all, so one publishing is enough
			break
		}
	} else {
		/* disable wireguard */
		err := p.publishWireguardPublicKey("")
		if err != nil {
			p.log.Errorf("Wireguard: publish PublicKey error %s", err)
		}
	}
}

func (p *WireguardProvider) createWireguardTunnels(nodeIP *net.IP, ipFamily string) error {
	if nodeIP == nil {
		return nil
	}
	p.log.Debugf("Adding wireguard Tunnel to VPP")
	tunnel := &vpptypes.WireguardTunnel{
		Addr: *nodeIP,
		Port: p.getWireguardPort(),
	}
	var swIfIndex uint32
	var err error
	if len(p.wireguardTunnels) != 0 { // we already have one, use same public key
		for _, tun := range p.wireguardTunnels {
			tunnel.PrivateKey = tun.PrivateKey
			break
		}
		swIfIndex, err = p.vpp.AddWireguardTunnel(tunnel, false /* generateKey */)
	} else {
		swIfIndex, err = p.vpp.AddWireguardTunnel(tunnel, true /* generateKey */)
	}

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
	tunnel.PrivateKey = createdTunnel.PrivateKey

	err = p.vpp.InterfaceSetUnnumbered(swIfIndex, common.VppManagerInfo.GetMainSwIfIndex())
	if err != nil {
		p.errorCleanup(tunnel)
		return errors.Wrapf(err, "Error setting wireguard tunnel unnumbered")
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

	common.SendEvent(common.CalicoVppEvent{
		Type: common.TunnelAdded,
		New:  swIfIndex,
	})

	p.wireguardTunnels[ipFamily] = tunnel
	p.log.Infof("connectivity(add) Wireguard Done tunnel=%s", p.wireguardTunnels)
	return nil
}

func (p *WireguardProvider) AddConnectivity(cn *common.NodeConnectivity) error {
	ipfamily := "ip4"
	if cn.NextHop.To4() == nil {
		ipfamily = "ip6"
	}
	if _, exists := p.wireguardTunnels[ipfamily]; !exists {
		return fmt.Errorf("wireguard: missing tunnel for ip family %s", ipfamily)
	}
	key, err := p.getNodePublicKey(cn)
	if err != nil {
		return errors.Wrapf(err, "Error Getting node %s publicKey", cn.NextHop)
	}
	peer := &vpptypes.WireguardPeer{
		PublicKey:  key,
		Port:       p.getWireguardPort(),
		Addr:       cn.NextHop,
		SwIfIndex:  p.wireguardTunnels[ipfamily].SwIfIndex,
		AllowedIps: []net.IPNet{cn.Dst, *common.ToMaxLenCIDR(cn.NextHop)},
	}
	existingPeer, found := p.wireguardPeers[cn.NextHop.String()]
	p.log.Infof("connectivity(add) Wireguard: NH=%s Dst=%s found=%t", cn.NextHop, cn.Dst, found)
	if found {
		peer.AllowedIps = existingPeer.AllowedIps
		peer.AddAllowedIp(cn.Dst)
		/* Only update if we need to */
		if !existingPeer.Equal(peer) {
			p.log.Infof("connectivity(add) Wireguard: Delete (update) peer=%s", existingPeer.String())
			err := p.vpp.DelWireguardPeer(&existingPeer)
			if err != nil {
				return errors.Wrapf(err, "Error deleting (update) wireguard peer=%s", existingPeer.String())
			}
			p.log.Infof("connectivity(add) Wireguard: Add back (update) peer=%s", peer)
			peer.Index, err = p.vpp.AddWireguardPeer(peer)
			if err != nil {
				return errors.Wrapf(err, "Error adding (update) wireguard peer=%s", peer)
			}
		}
	} else {
		p.log.Infof("connectivity(add) Wireguard: Add peer=%s", peer)
		peer.Index, err = p.vpp.AddWireguardPeer(peer)
		if err != nil {
			return errors.Wrapf(err, "Error adding wireguard peer [%s]", peer)
		}

		p.log.Debugf("Routing pod->node %s traffic into wg tunnel (swIfIndex %d)", cn.NextHop.String(), p.wireguardTunnels[ipfamily].SwIfIndex)
		err = p.vpp.RouteAdd(&types.Route{
			Dst: common.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: p.wireguardTunnels[ipfamily].SwIfIndex,
				Gw:        nil,
			}},
			Table: common.PodVRFIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "Error adding route to %s in wg tunnel %d for pods", cn.NextHop.String(), p.wireguardTunnels[ipfamily].SwIfIndex)
		}
	}
	p.log.Infof("connectivity(add) Wireguard tunnel done peer=%s", peer)
	p.wireguardPeers[cn.NextHop.String()] = *peer

	p.log.Debugf("Adding wireguard tunnel route to %s via swIfIndex %d", cn.Dst.IP, p.wireguardTunnels[ipfamily].SwIfIndex)
	err = p.vpp.RouteAdd(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: p.wireguardTunnels[ipfamily].SwIfIndex,
			Gw:        cn.Dst.IP,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error Adding route to wireguard tunnel")
	}
	return nil
}

func (p *WireguardProvider) DelConnectivity(cn *common.NodeConnectivity) (err error) {
	ipfamily := "ip4"
	if cn.NextHop.To4() == nil {
		ipfamily = "ip6"
	}
	if _, exists := p.wireguardTunnels[ipfamily]; !exists {
		return fmt.Errorf("wireguard: missing tunnel for ip family %s", ipfamily)
	}
	peer, found := p.wireguardPeers[cn.NextHop.String()]
	if !found {
		return errors.Errorf("Deleting unknown wireguard tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("connectivity(del) Wireguard cn=%s peer-index=%d", cn.String(), peer.Index)
	peer.DelAllowedIp(cn.Dst)

	if len(peer.AllowedIps) == 1 {
		err = p.vpp.DelWireguardPeer(&peer)
		if err != nil {
			return errors.Wrapf(err, "Error deleting wireguard peer %s", peer.String())
		}
		err = p.vpp.RouteDel(&types.Route{
			Dst: common.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: p.wireguardTunnels[ipfamily].SwIfIndex,
				Gw:        nil,
			}},
			Table: common.PodVRFIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "Error deleting route to %s in ipip tunnel %d for pods", cn.NextHop.String(), p.wireguardTunnels[ipfamily].SwIfIndex)
		}
		delete(p.wireguardPeers, cn.NextHop.String())
	} else {
		/* for now delete + recreate using modified object as delete
		 * doesn't consider AllowedIps */
		p.log.Infof("connectivity(del) Wireguard: Delete (update) peer=%s", peer.String())
		err = p.vpp.DelWireguardPeer(&peer)
		if err != nil {
			return errors.Wrapf(err, "Error deleting (update) wireguard peer %s", peer.String())
		}
		p.log.Infof("connectivity(del) Wireguard: Addback (update) peer=%s", peer.String())
		_, err = p.vpp.AddWireguardPeer(&peer)
		if err != nil {
			return errors.Wrapf(err, "Error adding (update) wireguard peer=%s", peer.String())
		}
		p.wireguardPeers[cn.NextHop.String()] = peer
	}
	err = p.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: peer.SwIfIndex,
			Gw:        cn.Dst.IP,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting wireguard tunnel route")
	}
	// We don't delete the interface so keep it in the map
	// p.wireguardV[46]Tunnel
	return nil
}
