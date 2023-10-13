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

	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type WireguardProvider struct {
	*ConnectivityProviderData
	wireguardTunnels   map[string]*vpptypes.WireguardTunnel
	wireguardPeers     map[string]*vpptypes.WireguardPeer
	nodesToWGPublicKey map[string]string
	wireguardRoutes    map[uint32]map[string]map[string]bool
}

func NewWireguardProvider(d *ConnectivityProviderData) *WireguardProvider {
	return &WireguardProvider{
		ConnectivityProviderData: d,
		wireguardTunnels:         make(map[string]*vpptypes.WireguardTunnel),
		wireguardPeers:           make(map[string]*vpptypes.WireguardPeer),
		nodesToWGPublicKey:       make(map[string]string),
		wireguardRoutes:          make(map[uint32]map[string]map[string]bool),
	}
}

func (self *WireguardProvider) Enabled(cn *common.NodeConnectivity) bool {
	felixConfig := self.GetFelixConfig()
	if !felixConfig.WireguardEnabled {
		return false
	}
	node := self.GetNodeByIp(cn.NextHop)
	return self.nodesToWGPublicKey[node.Name] != ""
}

func (self *WireguardProvider) getWireguardPort() uint16 {
	felixConfig := self.GetFelixConfig()
	if felixConfig.WireguardListeningPort == 0 {
		return uint16(config.DefaultWireguardPort)
	}
	return uint16(felixConfig.WireguardListeningPort)
}

func (self *WireguardProvider) getNodePublicKey(cn *common.NodeConnectivity) ([]byte, error) {
	node := self.GetNodeByIp(cn.NextHop)
	if self.nodesToWGPublicKey[node.Name] == "" {
		return nil, fmt.Errorf("no public key for node=%s", node.Name)
	}

	self.log.Infof("connectivity(add) Wireguard nodeName=%s pubKey=%s", node.Name, self.nodesToWGPublicKey[node.Name])
	key, err := base64.StdEncoding.DecodeString(self.nodesToWGPublicKey[node.Name])
	if err != nil {
		return nil, errors.Wrapf(err, "Error decoding wireguard public key %s", self.nodesToWGPublicKey[node.Name])
	}
	return key, nil
}

func (self *WireguardProvider) publishWireguardPublicKey(pubKey string) error {
	// Ref: felix/daemon/daemon.go:1056
	node, err := self.Clientv3().Nodes().Get(context.Background(), *config.NodeName, options.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Error getting node config")
	}
	self.log.Infof("connectivity(add) Wireguard publishing nodeName=%s pubKey=%s", *config.NodeName, pubKey)
	node.Status.WireguardPublicKey = pubKey
	_, err = self.Clientv3().Nodes().Update(context.Background(), node, options.SetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Error updating node config")
	}
	return nil
}

func (self *WireguardProvider) RescanState() {
	self.wireguardPeers = make(map[string]*vpptypes.WireguardPeer)
	self.wireguardTunnels = make(map[string]*vpptypes.WireguardTunnel)
	self.wireguardRoutes = make(map[uint32]map[string]map[string]bool)

	self.log.Debugf("Wireguard: Rescanning existing tunnels")
	tunnels, err := self.vpp.ListWireguardTunnels()
	if err != nil {
		self.log.Errorf("Error listing wireguard tunnels: %v", err)
	}
	for _, tunnel := range tunnels {
		self.log.Infof("Found existing tunnel: %s", tunnel)
		self.wireguardTunnels[tunnel.Addr.String()] = tunnel
		self.wireguardRoutes[tunnel.SwIfIndex] = make(map[string]map[string]bool)
	}

	self.log.Debugf("Wireguard: Rescanning existing peers")
	peers, err := self.vpp.ListWireguardPeers()
	if err != nil {
		self.log.Errorf("Error listing wireguard peers: %v", err)
	}

	for _, peer := range peers {
		self.wireguardPeers[peer.Addr.String()] = peer
		if _, exist := self.wireguardRoutes[peer.SwIfIndex]; !exist {
			self.log.Errorf("Peer found for non WG tunnel: %v", peer)
			continue
		}
		self.wireguardRoutes[peer.SwIfIndex][peer.Addr.String()] = make(map[string]bool)
	}

	routes, err := self.vpp.GetRoutes(0, false)
	if err != nil {
		self.log.Errorf("Error listing routes: %v", err)
	}
	for _, route := range routes {
		for _, routePath := range route.Paths {
			_, exists := self.wireguardRoutes[routePath.SwIfIndex]
			if exists {
				self.wireguardRoutes[routePath.SwIfIndex][routePath.Gw.String()][route.Dst.String()] = true
			}
		}
	}
}

func (self *WireguardProvider) errorCleanup(tunnel *vpptypes.WireguardTunnel) {
	err := self.vpp.DelWireguardTunnel(tunnel)
	if err != nil {
		self.log.Errorf("Error deleting wireguard tunnel %s after error: %v", tunnel.String(), err)
	}
}

func (self *WireguardProvider) EnableDisable(isEnable bool) {
	if isEnable {
		if len(self.wireguardTunnels) == 0 {
			err := self.createWireguardTunnels()
			if err != nil {
				self.log.Errorf("Wireguard: Error creating v4 tunnel %s", err)
				return
			}
		}

		for _, tun := range self.wireguardTunnels {
			key := base64.StdEncoding.EncodeToString(tun.PublicKey)
			err := self.publishWireguardPublicKey(key)
			if err != nil {
				self.log.Errorf("Wireguard: publish PublicKey error %s", err)
			}
			// should be the same for all, so one publishing is enough
			break
		}
	} else {
		/* disable wireguard */
		err := self.publishWireguardPublicKey("")
		if err != nil {
			self.log.Errorf("Wireguard: publish PublicKey error %s", err)
		}
	}
}

func (self *WireguardProvider) createWireguardTunnels() error {
	ip4, ip6 := self.server.GetNodeIPs()
	for _, nodeIp := range []*net.IP{ip4, ip6} {
		if nodeIp == nil {
			continue
		}
		tunnel := &vpptypes.WireguardTunnel{
			Addr: *nodeIp,
			Port: self.getWireguardPort(),
		}
		generateKey := true
		for _, tun := range self.wireguardTunnels {
			// If we already have tunnel (v4 or v6), use the same public
			// key for the other one
			tunnel.PrivateKey = tun.PrivateKey
			generateKey = false
			break
		}
		swIfIndex, err := self.vpp.AddWireguardTunnel(tunnel, generateKey)
		if err != nil {
			self.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error creating wireguard tunnel")
		}
		// fetch public key of created tunnel
		createdTunnel, err := self.vpp.GetWireguardTunnel(swIfIndex)
		if err != nil {
			self.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error fetching wireguard tunnel after creation")
		}
		tunnel.PublicKey = createdTunnel.PublicKey
		tunnel.PrivateKey = createdTunnel.PrivateKey

		err = self.vpp.InterfaceSetUnnumbered(swIfIndex, common.VppManagerInfo.GetMainSwIfIndex())
		if err != nil {
			self.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error setting wireguard tunnel unnumbered")
		}

		err = self.vpp.EnableGSOFeature(swIfIndex)
		if err != nil {
			self.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error enabling gso for wireguard interface")
		}

		err = self.vpp.CnatEnableFeatures(swIfIndex)
		if err != nil {
			self.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error enabling nat for wireguard interface")
		}

		err = self.vpp.InterfaceAdminUp(swIfIndex)
		if err != nil {
			self.errorCleanup(tunnel)
			return errors.Wrapf(err, "Error setting wireguard interface up")
		}

		common.SendEvent(common.CalicoVppEvent{
			Type: common.TunnelAdded,
			New:  swIfIndex,
		})

		self.wireguardTunnels[nodeIp.String()] = tunnel

		self.wireguardRoutes[tunnel.SwIfIndex] = make(map[string]map[string]bool)
	}
	self.log.Infof("connectivity(add) Wireguard Done tunnel=%s", self.wireguardTunnels)
	return nil
}

func (self *WireguardProvider) getTunnelForIpFamily(cn *common.NodeConnectivity) *vpptypes.WireguardTunnel {
	for _, tun := range self.wireguardTunnels {
		if vpplink.IpFamilyFromIP(&tun.Addr) == vpplink.IpFamilyFromIP(&cn.NextHop) {
			return tun
		}
	}
	return nil

}

func (self *WireguardProvider) AddConnectivity(cn *common.NodeConnectivity) error {
	wireguardTunnel := self.getTunnelForIpFamily(cn)
	if wireguardTunnel == nil {
		return fmt.Errorf("Wireguard: missing tunnel for ip family %s", cn)
	}
	key, err := self.getNodePublicKey(cn)
	if err != nil {
		return errors.Wrapf(err, "Error Getting node %s publicKey", cn.NextHop)
	}

	peer, found := self.wireguardPeers[cn.NextHop.String()]
	self.log.Infof("connectivity(add) Wireguard: NH=%s Dst=%s found=%t", cn.NextHop, cn.Dst, found)
	if !found {
		peer = &vpptypes.WireguardPeer{
			PublicKey:  key,
			Port:       self.getWireguardPort(),
			Addr:       cn.NextHop,
			SwIfIndex:  wireguardTunnel.SwIfIndex,
			AllowedIps: []net.IPNet{*common.ToMaxLenCIDR(cn.NextHop)},
		}

		self.log.Infof("connectivity(add) Wireguard: Add peer=%s", peer)
		peer.Index, err = self.vpp.AddWireguardPeer(peer)
		if err != nil {
			return errors.Wrapf(err, "Error adding wireguard peer [%s]", peer)
		}
		self.wireguardRoutes[wireguardTunnel.SwIfIndex][cn.NextHop.String()] = make(map[string]bool)

		self.log.Debugf("Routing pod->node %s traffic into wg tunnel (swIfIndex %d)", cn.NextHop.String(), wireguardTunnel.SwIfIndex)
		err = self.vpp.RouteAdd(&types.Route{
			Dst: common.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: wireguardTunnel.SwIfIndex,
				Gw:        cn.NextHop,
			}},
			Table: common.PodVRFIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "Error adding route to %s in wg tunnel %d for pods", cn.NextHop.String(), wireguardTunnel.SwIfIndex)
		}
		self.wireguardPeers[cn.NextHop.String()] = peer
	}
	self.log.Infof("connectivity(add) Wireguard tunnel done peer=%s", peer)

	self.log.Debugf("Adding wireguard tunnel route to %s via swIfIndex %d", cn.Dst.IP, wireguardTunnel.SwIfIndex)
	err = self.vpp.RouteAdd(&types.Route{
		Dst: &cn.Dst,
		// This picks the adjacency defined in peer.AllowedIps
		Paths: []types.RoutePath{{
			SwIfIndex: wireguardTunnel.SwIfIndex,
			Gw:        cn.NextHop,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error Adding route to wireguard tunnel")
	}
	self.wireguardRoutes[wireguardTunnel.SwIfIndex][cn.NextHop.String()][cn.Dst.String()] = true
	return nil
}

func (self *WireguardProvider) DelConnectivity(cn *common.NodeConnectivity) (err error) {
	wireguardTunnel := self.getTunnelForIpFamily(cn)
	if wireguardTunnel == nil {
		return fmt.Errorf("Wireguard: missing tunnel for ip family %s", cn)
	}
	peer, found := self.wireguardPeers[cn.NextHop.String()]
	if !found {
		return errors.Errorf("Deleting unknown wireguard tunnel %s", cn.NextHop.String())
	}
	self.log.Infof("connectivity(del) Wireguard cn=%s peer-index=%d", cn.String(), peer.Index)

	err = self.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: peer.SwIfIndex,
			Gw:        cn.NextHop,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting wireguard tunnel route")
	}
	delete(self.wireguardRoutes[wireguardTunnel.SwIfIndex][cn.NextHop.String()], cn.Dst.String())
	if len(self.wireguardRoutes[wireguardTunnel.SwIfIndex][cn.NextHop.String()]) == 0 {
		self.log.Infof("connectivity(del) Wireguard peer GONE cn=%s peer-index=%d", cn.String(), peer.Index)
		err = self.vpp.DelWireguardPeer(peer)
		if err != nil {
			return errors.Wrapf(err, "Error deleting wireguard peer %s", peer.String())
		}
		delete(self.wireguardRoutes[wireguardTunnel.SwIfIndex], cn.NextHop.String())

		err = self.vpp.RouteDel(&types.Route{
			Dst: common.ToMaxLenCIDR(cn.NextHop),
			Paths: []types.RoutePath{{
				SwIfIndex: wireguardTunnel.SwIfIndex,
				Gw:        cn.NextHop,
			}},
			Table: common.PodVRFIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "Error deleting route to %s in ipip tunnel %d for pods", cn.NextHop.String(), wireguardTunnel.SwIfIndex)
		}
		delete(self.wireguardPeers, cn.NextHop.String())
	}

	return nil
}
