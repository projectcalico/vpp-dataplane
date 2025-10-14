// Copyright (C) 2025 Cisco Systems Inc.
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

package routing

import (
	"net"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

// SecretGetter is an interface for retrieving secrets by name and key
type SecretGetter interface {
	GetSecret(name, key string) (string, error)
}

// BGPPeerState represents the state of a BGP peer
type BGPPeerState struct {
	AS            uint32
	SweepFlag     bool
	BGPPeerSpec   *calicov3.BGPPeerSpec
	SecretChanged bool
}

// PeerHandler handles BGP peer configuration and business logic
type PeerHandler struct {
	log   *logrus.Entry
	cache *cache.Cache

	nodeStatesByName map[string]common.LocalNodeSpec

	secretWatcher SecretGetter
	state         map[string]*BGPPeerState // peer IP -> state
}

// NewPeerHandler creates a new PeerHandler
func NewPeerHandler(cache *cache.Cache, log *logrus.Entry) *PeerHandler {
	handler := &PeerHandler{
		log:              log,
		cache:            cache,
		nodeStatesByName: make(map[string]common.LocalNodeSpec),
		state:            make(map[string]*BGPPeerState),
	}

	return handler
}

// SetSecretWatcher sets the secret watcher
func (h *PeerHandler) SetSecretWatcher(secretWatcher SecretGetter) {
	h.secretWatcher = secretWatcher
}

// selectsNode determines whether or not the selector mySelector
// matches the labels on the given node.
func (h *PeerHandler) selectsNode(mySelector string, n *common.LocalNodeSpec) (bool, error) {
	// No node selector means that the selector matches the node.
	if len(mySelector) == 0 {
		return true, nil
	}
	// Check for valid selector syntax.
	sel, err := selector.Parse(mySelector)
	if err != nil {
		return false, err
	}
	// Return whether or not the selector matches.
	return sel.Evaluate(n.Labels), nil
}

func (h *PeerHandler) shouldPeer(peer *calicov3.BGPPeer) bool {
	matches, err := h.selectsNode(peer.Spec.NodeSelector, h.currentCalicoNode())
	if err != nil {
		h.log.Error(errors.Wrapf(err, "Error in nodeSelector matching for peer %s", peer.Name))
	}
	if (peer.Spec.Node != "" && peer.Spec.Node != *config.NodeName) || (peer.Spec.NodeSelector != "" && !matches) {
		return false
	}
	return true
}

func (h *PeerHandler) getAsNumber(node *common.LocalNodeSpec) uint32 {
	if node.ASNumber == nil {
		return uint32(*h.cache.BGPConf.ASNumber)
	} else {
		return uint32(*node.ASNumber)
	}
}

// Select among the nodes those that match with peerSelector
// Return corresponding ips and ASN in a map
func (h *PeerHandler) selectPeers(peerSelector string) map[string]uint32 {
	ipAsn := make(map[string]uint32)
	for _, node := range h.nodeStatesByName {
		if node.Name == *config.NodeName {
			continue // Don't peer with ourselves :)
		}
		matches, err := h.selectsNode(peerSelector, &node)
		if err != nil {
			h.log.Errorf("Error in peerSelector matching: %v", err)
		}
		if matches {
			if node.IPv4Address != nil && h.currentCalicoNode().IPv4Address != nil {
				ipAsn[node.IPv4Address.IP.String()] = h.getAsNumber(&node)
			}
			if node.IPv6Address != nil && h.currentCalicoNode().IPv6Address != nil {
				ipAsn[node.IPv6Address.IP.String()] = h.getAsNumber(&node)
			}
		}
	}
	return ipAsn
}

func (h *PeerHandler) currentCalicoNode() *common.LocalNodeSpec {
	node := h.nodeStatesByName[*config.NodeName]
	return &node
}

func (h *PeerHandler) isMeshMode() bool {
	if h.cache.BGPConf.NodeToNodeMeshEnabled != nil {
		return *h.cache.BGPConf.NodeToNodeMeshEnabled
	}
	return true
}

// Given peer's BGPPeerConf check if Password is set and return secret name
func (h *PeerHandler) getSecretName(spec *calicov3.BGPPeerSpec) string {
	if spec.Password != nil && spec.Password.SecretKeyRef != nil {
		return spec.Password.SecretKeyRef.Name
	}
	return ""
}

func (h *PeerHandler) createBGPPeer(ip string, asn uint32, secretValue string) (*bgpapi.Peer, error) {
	h.log.Infof("createBGPPeer with ip %s", ip)
	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, err
	}

	typ := &common.BgpFamilyUnicastIPv4
	typSRv6 := &common.BgpFamilySRv6IPv6
	typvpn4 := &common.BgpFamilyUnicastIPv4VPN
	typvpn6 := &common.BgpFamilyUnicastIPv6VPN

	if ipAddr.IP.To4() == nil {
		typ = &common.BgpFamilyUnicastIPv6
	}

	afiSafis := []*bgpapi.AfiSafi{
		{
			Config: &bgpapi.AfiSafiConfig{
				Family:  typ,
				Enabled: true,
			},
			MpGracefulRestart: &bgpapi.MpGracefulRestart{
				Config: &bgpapi.MpGracefulRestartConfig{
					Enabled: true,
				},
			},
		},
		{
			Config: &bgpapi.AfiSafiConfig{
				Family:  typSRv6,
				Enabled: true,
			},
		},
		{
			Config: &bgpapi.AfiSafiConfig{
				Family:  typvpn4,
				Enabled: true,
			},
		},
		{
			Config: &bgpapi.AfiSafiConfig{
				Family:  typvpn6,
				Enabled: true,
			},
		},
	}
	peer := &bgpapi.Peer{
		Conf: &bgpapi.PeerConf{
			NeighborAddress: ipAddr.String(),
			PeerAsn:         asn,
		},
		GracefulRestart: &bgpapi.GracefulRestart{
			Enabled:             true,
			RestartTime:         120,
			LonglivedEnabled:    true,
			NotificationEnabled: true,
		},
		AfiSafis: afiSafis,
	}

	if secretValue != "" {
		peer.Conf.AuthPassword = secretValue
	}
	return peer, nil
}

func (h *PeerHandler) addBGPPeer(ip string, asn uint32, peerSpec *calicov3.BGPPeerSpec, secretValue string) error {
	peer, err := h.createBGPPeer(ip, asn, secretValue)
	if err != nil {
		return errors.Wrap(err, "cannot add bgp peer")
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerAdded,
		New:  &LocalBGPPeer{Peer: peer, BGPFilterNames: peerSpec.Filters},
	})
	return nil
}

func (h *PeerHandler) updateBGPPeer(ip string, asn uint32, peerSpec, oldPeerSpec *calicov3.BGPPeerSpec, secretValue string) error {
	peer, err := h.createBGPPeer(ip, asn, secretValue)
	if err != nil {
		return errors.Wrap(err, "cannot update bgp peer")
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerUpdated,
		New:  &LocalBGPPeer{Peer: peer, BGPFilterNames: peerSpec.Filters},
		Old:  &LocalBGPPeer{BGPFilterNames: oldPeerSpec.Filters},
	})
	return nil
}

func (h *PeerHandler) deleteBGPPeer(ip string) error {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerDeleted,
		Old:  ip,
	})
	return nil
}

// ProcessPeers processes a list of BGP peers and reconciles them
func (h *PeerHandler) ProcessPeers(peers []calicov3.BGPPeer) error {
	h.log.Debugf("Processing %d BGP peers", len(peers))

	// Start mark and sweep
	for _, p := range h.state {
		p.SweepFlag = true
	}

	// If in mesh mode, add a fake peer to the list to select all nodes
	if h.isMeshMode() {
		h.log.Debugf("Node to node mesh enabled")
		peers = append(peers, calicov3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name: "<internal> virtual full mesh peer",
			},
			Spec: calicov3.BGPPeerSpec{
				Node:         *config.NodeName,
				PeerSelector: "all()",
			},
		})
	} else {
		h.log.Debugf("Node to node mesh disabled")
	}

	// Process all peers
	for _, peer := range peers {
		if !h.shouldPeer(&peer) {
			continue
		}
		ipAsn := make(map[string]uint32)
		if peer.Spec.PeerSelector != "" {
			// this peer has a peerSelector, use it
			ipAsn = h.selectPeers(peer.Spec.PeerSelector)
		} else {
			// use peerIP and ASNumber specified in the peer
			ipAsn[peer.Spec.PeerIP] = uint32(peer.Spec.ASNumber)
		}
		for ip, asn := range ipAsn {
			existing, ok := h.state[ip]
			if ok {
				h.log.Debugf("peer(update) neighbor ip=%s for BGPPeer=%s", ip, peer.Name)
				existing.SweepFlag = false
				oldSecret := h.getSecretName(existing.BGPPeerSpec)
				newSecret := h.getSecretName(&peer.Spec)

				// Get the secret value if needed
				secretValue := ""
				if newSecret != "" {
					secretValue = h.getSecretValue(&peer.Spec)
				}

				if oldSecret != newSecret || existing.SecretChanged {
					h.log.Infof("peer(upd-secret) neighbor ip=%s oldSecret=%s newSecret=%s", ip, oldSecret, newSecret)
					err := h.updateBGPPeer(ip, asn, &peer.Spec, existing.BGPPeerSpec, secretValue)
					if err != nil {
						return errors.Wrapf(err, "Error updating bgp peer %s", ip)
					}
					existing.BGPPeerSpec = &peer.Spec
					existing.SecretChanged = false
				} else {
					h.log.Debugf("peer(same) neighbor ip=%s", ip)
				}
			} else {
				// New peer
				h.log.Infof("peer(add) neighbor ip=%s for BGPPeer=%s", ip, peer.Name)

				// Get the secret value if needed
				secretValue := ""
				secretName := h.getSecretName(&peer.Spec)
				if secretName != "" {
					secretValue = h.getSecretValue(&peer.Spec)
				}

				err := h.addBGPPeer(ip, asn, &peer.Spec, secretValue)
				if err != nil {
					return errors.Wrapf(err, "Error adding bgp peer %s", ip)
				}
				h.state[ip] = &BGPPeerState{
					AS:            asn,
					SweepFlag:     false,
					BGPPeerSpec:   &peer.Spec,
					SecretChanged: false,
				}
			}
		}
	}

	// Remove all peers that still have sweepflag to true
	for ip, peer := range h.state {
		if peer.SweepFlag {
			h.log.Infof("peer(del) neighbor ip=%s", ip)
			err := h.deleteBGPPeer(ip)
			if err != nil {
				return errors.Wrapf(err, "Error deleting bgp peer %s", ip)
			}
			delete(h.state, ip)
		}
	}

	return nil
}

// getSecretValue retrieves the actual secret value from the secret watcher
func (h *PeerHandler) getSecretValue(spec *calicov3.BGPPeerSpec) string {
	if spec.Password == nil || spec.Password.SecretKeyRef == nil {
		return ""
	}

	secretName := spec.Password.SecretKeyRef.Name
	secretKey := spec.Password.SecretKeyRef.Key

	value, err := h.secretWatcher.GetSecret(secretName, secretKey)
	if err != nil {
		h.log.Warnf("Error getting secret %s key %s: %v", secretName, secretKey, err)
		return ""
	}

	return value
}

// OnPeerNodeStateChanged handles peer node state changes
func (h *PeerHandler) OnPeerNodeStateChanged(old, new *common.LocalNodeSpec) {
	if old != nil {
		delete(h.nodeStatesByName, old.Name)
	}
	if new != nil {
		h.nodeStatesByName[new.Name] = *new
	}
	h.log.Debugf("Nodes updated in peer handler, old %v new %v", old, new)
}

// OnSecretChanged handles secret changes
func (h *PeerHandler) OnSecretChanged(secretName string) {
	h.log.Infof("Secret '%s' changed, marking affected peers for update", secretName)

	// sweep through the peers and update the SecretChanged field of impacted peers
	for _, peer := range h.state {
		if h.getSecretName(peer.BGPPeerSpec) == secretName {
			h.log.Infof("SecretChanged field set for peer=%s", peer.BGPPeerSpec.PeerIP)
			peer.SecretChanged = true
		}
	}
}
