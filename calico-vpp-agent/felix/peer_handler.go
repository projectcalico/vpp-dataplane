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

package felix

import (
	"net"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

// PeerHandler handles BGP peer configuration and business logic
type PeerHandler struct {
	log      *logrus.Entry
	clientv3 calicov3cli.Interface
	cache    *cache.Cache

	nodeStatesByName map[string]common.LocalNodeSpec
	BGPConf          *calicov3.BGPConfigurationSpec

	// Interface to get BGP secrets
	secretGetter SecretGetter
	// Interface to handle BGP secrets cleanup
	secretCleanupHandler SecretCleanupHandler
}

// SecretGetter interface for getting BGP secrets
type SecretGetter interface {
	GetSecret(name, key string) (string, error)
}

// SecretCleanupHandler interface for handling BGP secrets cleanup
type SecretCleanupHandler interface {
	SweepStale(activeSecrets map[string]struct{})
}

// NewPeerHandler creates a new PeerHandler (events are sent directly to this handler)
func NewPeerHandler(clientv3 calicov3cli.Interface, cache *cache.Cache, secretGetter SecretGetter, secretCleanupHandler SecretCleanupHandler, log *logrus.Entry) *PeerHandler {
	handler := &PeerHandler{
		log:                  log,
		clientv3:             clientv3,
		cache:                cache,
		nodeStatesByName:     make(map[string]common.LocalNodeSpec),
		secretGetter:         secretGetter,
		secretCleanupHandler: secretCleanupHandler,
	}

	return handler
}

func (h *PeerHandler) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	h.BGPConf = bgpConf
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
		return uint32(*h.BGPConf.ASNumber)
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
	if h.BGPConf.NodeToNodeMeshEnabled != nil {
		return *h.BGPConf.NodeToNodeMeshEnabled
	}
	return true
}

// Given peer's BGPPeerConf check if Password is set and return SecretKeyRef
func (h *PeerHandler) getSecretKeyRef(spec *calicov3.BGPPeerSpec) *v1.SecretKeySelector {
	if spec.Password != nil && spec.Password.SecretKeyRef != nil {
		return spec.Password.SecretKeyRef
	}
	return nil
}

// Given peer's BGPPeerConf check if Password is set and return secret name
func (h *PeerHandler) getSecretName(spec *calicov3.BGPPeerSpec) string {
	if spec.Password != nil && spec.Password.SecretKeyRef != nil {
		return spec.Password.SecretKeyRef.Name
	}
	return ""
}

// Get the BGP password from SecretWatcher
func (h *PeerHandler) getPassword(secretKeySelector *v1.SecretKeySelector) (string, error) {
	password, err := h.secretGetter.GetSecret(
		secretKeySelector.Name,
		secretKeySelector.Key,
	)
	return password, err
}

func (h *PeerHandler) createBGPPeer(ip string, asn uint32, peerSpec *calicov3.BGPPeerSpec) (*bgpapi.Peer, error) {
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

	if h.getSecretKeyRef(peerSpec) != nil {
		peer.Conf.AuthPassword, err = h.getPassword(peerSpec.Password.SecretKeyRef)
		if err != nil {
			return nil, err
		}
	}
	return peer, nil
}

func (h *PeerHandler) addBGPPeer(ip string, asn uint32, peerSpec *calicov3.BGPPeerSpec) error {
	peer, err := h.createBGPPeer(ip, asn, peerSpec)
	if err != nil {
		return errors.Wrap(err, "cannot add bgp peer")
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerAdded,
		New:  &watchers.LocalBGPPeer{Peer: peer, BGPFilterNames: peerSpec.Filters},
	})
	return nil
}

func (h *PeerHandler) updateBGPPeer(ip string, asn uint32, peerSpec, oldPeerSpec *calicov3.BGPPeerSpec) error {
	peer, err := h.createBGPPeer(ip, asn, peerSpec)
	if err != nil {
		return errors.Wrap(err, "cannot update bgp peer")
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerUpdated,
		New:  &watchers.LocalBGPPeer{Peer: peer, BGPFilterNames: peerSpec.Filters},
		Old:  &watchers.LocalBGPPeer{BGPFilterNames: oldPeerSpec.Filters},
	})
	return nil
}

func (h *PeerHandler) deleteBGPPeer(ip string) error {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerDeleted,
		New:  ip,
	})
	return nil
}

// ProcessPeers processes a list of BGP peers and reconciles them
func (h *PeerHandler) ProcessPeers(peers []calicov3.BGPPeer, state map[string]*common.BGPPeerState) error {
	h.log.Debugf("Processing %d BGP peers", len(peers))

	// Start mark and sweep
	for _, p := range state {
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

	// Initialize the set consisting of active secrets
	activeSecrets := map[string]struct{}{}
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
			existing, ok := state[ip]
			if ok {
				h.log.Debugf("peer(update) neighbor ip=%s for BGPPeer=%s", ip, peer.Name)
				existing.SweepFlag = false
				oldSecret := h.getSecretName(existing.BGPPeerSpec)
				newSecret := h.getSecretName(&peer.Spec)
				h.log.Debugf("peer(update) oldSecret=%s newSecret=%s SecretChanged=%t for BGPPeer=%s", oldSecret, newSecret, existing.SecretChanged, peer.Name)
				filtersChanged := !watchers.CompareStringSlices(existing.BGPPeerSpec.Filters, peer.Spec.Filters)
				if existing.AS != asn || oldSecret != newSecret || existing.SecretChanged || filtersChanged {
					err := h.updateBGPPeer(ip, asn, &peer.Spec, existing.BGPPeerSpec)
					if err != nil {
						h.log.Warn(errors.Wrapf(err, "error updating BGP peer %s, ip=%s", peer.Name, ip))
						continue
					}
					existing.AS = asn
					existing.BGPPeerSpec = peer.Spec.DeepCopy()
					existing.SecretChanged = false
				} // Else no change, nothing to do
			} else {
				// New peer
				h.log.Infof("peer(add) neighbor ip=%s for BGPPeer=%s", ip, peer.Name)
				err := h.addBGPPeer(ip, asn, &peer.Spec)
				if err != nil {
					h.log.Warn(errors.Wrapf(err, "error adding BGP peer %s, ip=%s", peer.Name, ip))
					// Add the secret to the set of active secrets so it does not get cleaned up
					secretName := h.getSecretName(&peer.Spec)
					if secretName != "" {
						activeSecrets[secretName] = struct{}{}
					}
					continue
				}
				state[ip] = &common.BGPPeerState{
					AS:            asn,
					SweepFlag:     false,
					SecretChanged: false,
					BGPPeerSpec:   peer.Spec.DeepCopy(),
				}
			}
		}
	}
	// Remove all peers that still have sweepflag to true
	for ip, peer := range state {
		if peer.SweepFlag {
			h.log.Infof("peer(del) neighbor ip=%s", ip)
			err := h.deleteBGPPeer(ip)
			if err != nil {
				h.log.Warn(errors.Wrapf(err, "error deleting BGP peer %s", ip))
			}
			delete(state, ip)
		}
	}
	// Clean up any secrets that are no longer referenced by any bgp peers
	for _, peer := range state {
		secretName := h.getSecretName(peer.BGPPeerSpec)
		if secretName != "" {
			activeSecrets[secretName] = struct{}{}
		}
	}

	// Directly notify the secret cleanup handler about active secrets
	if h.secretCleanupHandler != nil {
		h.secretCleanupHandler.SweepStale(activeSecrets)
	}

	return nil
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
func (h *PeerHandler) OnSecretChanged(secretName string, state map[string]*common.BGPPeerState) {
	h.log.Infof("Secret '%s' changed, updating affected peers", secretName)

	// sweep through the peers and update the SecretChanged field of impacted peers
	for _, peer := range state {
		if h.getSecretName(peer.BGPPeerSpec) == secretName {
			h.log.Infof("SecretChanged field set for peer=%s", peer.BGPPeerSpec.PeerIP)
			peer.SecretChanged = true
		}
	}
}
