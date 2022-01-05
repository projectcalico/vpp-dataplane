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

package watchers

import (
	"net"

	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PeerWatcher struct {
	*common.RoutingData
	log *logrus.Entry

	nodeWatcher       *NodeWatcher
	nodeUpdates       chan bool
	currentCalicoNode *oldv3.Node
}

type bgpPeer struct {
	AS        uint32
	SweepFlag bool
}

// selectsNode determines whether or not the selector mySelector
// matches the labels on the given node.
func selectsNode(mySelector string, n *oldv3.Node) (bool, error) {
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

func (w *PeerWatcher) shouldPeer(peer *calicov3.BGPPeer) bool {
	matches, err := selectsNode(peer.Spec.NodeSelector, w.currentCalicoNode)
	if err != nil {
		w.log.Error(errors.Wrapf(err, "Error in nodeSelector matching for peer %s", peer.Name))
	}
	if (peer.Spec.Node != "" && peer.Spec.Node != config.NodeName) || (peer.Spec.NodeSelector != "" && !matches) {
		return false
	}
	return true
}

func (w *PeerWatcher) getAsNumber(node *oldv3.Node) uint32 {
	if node.Spec.BGP.ASNumber == nil {
		return uint32(*w.BGPConf.ASNumber)
	} else {
		return uint32(*node.Spec.BGP.ASNumber)
	}
}

// Select among the nodes those that match with peerSelector
// Return corresponding ips and ASN in a map
func (w *PeerWatcher) selectPeers(nodes []*oldv3.Node, peerSelector string) map[string]uint32 {
	ipAsn := make(map[string]uint32)
	for _, node := range nodes {
		if node.Name == config.NodeName {
			continue // Don't peer with ourselves :)
		}
		matches, err := selectsNode(peerSelector, node)
		if err != nil {
			w.log.Errorf("Error in peerSelector matching: %v", err)
		}
		if matches {
			if node.Spec.BGP.IPv4Address != "" && w.currentCalicoNode.Spec.BGP.IPv4Address != "" {
				ad, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
				if err == nil {
					ipAsn[ad.String()] = w.getAsNumber(node)
				} else {
					w.log.Warnf("Can't parse node IPv4: %s", node.Spec.BGP.IPv4Address)
				}
			}
			if node.Spec.BGP.IPv6Address != "" && w.currentCalicoNode.Spec.BGP.IPv6Address != "" {
				ad, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
				if err == nil {
					ipAsn[ad.String()] = w.getAsNumber(node)
				} else {
					w.log.Warnf("Can't parse node IPv6: %s", node.Spec.BGP.IPv6Address)
				}
			}
		}
	}
	return ipAsn
}

// This function watches BGP peers configured in Calico
// These peers are configured in GoBGP in addition to the other nodes in the cluster
// They may also control which nodes to pair with if the peerSelector is set
func (w *PeerWatcher) WatchBGPPeers() error {
	state := make(map[string]*bgpPeer)

	for {
		w.log.Debugf("Reconciliating peers...")
		peers, err := w.Clientv3.BGPPeers().List(context.Background(), options.ListOptions{})
		if err != nil {
			return err
		}
		nodes := w.nodeWatcher.GetNodesList()
		for _, node := range nodes {
			if node.Name == config.NodeName {
				w.currentCalicoNode = node
			}
		}
		// Start mark and sweep
		for _, p := range state {
			p.SweepFlag = true
		}
		// If in mesh mode, add a fake peer to the list to select all nodes
		if w.isMeshMode() {
			w.log.Debugf("Node to node mesh enabled")
			peers.Items = append(peers.Items, calicov3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "<internal> virtual full mesh peer",
				},
				Spec: calicov3.BGPPeerSpec{
					Node:         config.NodeName,
					PeerSelector: "all()",
				},
			})
		} else {
			w.log.Debugf("Node to node mesh disabled")
		}
		for _, peer := range peers.Items {
			if !w.shouldPeer(&peer) {
				continue
			}
			ipAsn := make(map[string]uint32)
			if peer.Spec.PeerSelector != "" {
				// this peer has a peerSelector, use it
				ipAsn = w.selectPeers(nodes, peer.Spec.PeerSelector)
			} else {
				// use peerIP and ASNumber specified in the peer
				ipAsn[peer.Spec.PeerIP] = uint32(peer.Spec.ASNumber)
			}
			for ip, asn := range ipAsn {
				existing, ok := state[ip]
				if ok {
					existing.SweepFlag = false
					if existing.AS != asn {
						existing.AS = asn
						err := w.updateBGPPeer(ip, asn)
						if err != nil {
							return errors.Wrap(err, "error updating BGP peer")
						}
					}
					// Else no change, nothing to do
				} else {
					// New peer
					w.log.Infof("Adding neighbor %s for BGPPeer %s", ip, peer.ObjectMeta.Name)
					state[ip] = &bgpPeer{
						AS:        asn,
						SweepFlag: false,
					}
					err := w.addBGPPeer(ip, asn)
					if err != nil {
						return errors.Wrap(err, "error adding BGP peer")
					}
				}
			}
		}
		// Remove all peers that still have sweepflag to true
		for ip, peer := range state {
			if peer.SweepFlag {
				err := w.deleteBGPPeer(ip)
				if err != nil {
					return errors.Wrap(err, "error deleting BGP peer")
				}
				delete(state, ip)
			}
		}

		revision := peers.ResourceVersion
		watcher, err := w.Clientv3.BGPPeers().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: revision},
		)
		if err != nil {
			return err
		}
		peerUpdatesChan := watcher.ResultChan()
		// node and peer updates should be infrequent enough - just reevaluate all peerings everytime there is an update
		select {
		case <-peerUpdatesChan:
			w.log.Debug("Peers updated, reevaluating peerings")
		case <-w.nodeUpdates:
			w.log.Debug("Nodes updated, reevaluating peerings")
		}
	}
}

func (w *PeerWatcher) createBGPPeer(ip string, asn uint32) (*bgpapi.Peer, error) {
	w.log.Infof("createBGPPeer with ip %s", ip)
	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, err
	}

	typ := &common.BgpFamilyUnicastIPv4
	typSRv6 := &common.BgpFamilySRv6IPv6
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
		&bgpapi.AfiSafi{
			Config: &bgpapi.AfiSafiConfig{
				Family:  typSRv6,
				Enabled: true,
			},
		},
	}
	peer := &bgpapi.Peer{
		Conf: &bgpapi.PeerConf{
			NeighborAddress: ipAddr.String(),
			PeerAs:          asn,
		},
		GracefulRestart: &bgpapi.GracefulRestart{
			Enabled:             true,
			RestartTime:         120,
			LonglivedEnabled:    true,
			NotificationEnabled: true,
		},
		AfiSafis: afiSafis,
	}
	return peer, nil
}

func (w *PeerWatcher) addBGPPeer(ip string, asn uint32) error {
	peer, err := w.createBGPPeer(ip, asn)
	if err != nil {
		return err
	}
	w.log.Infof("Adding BGP neighbor: %s AS:%d", peer.Conf.NeighborAddress, peer.Conf.PeerAs)
	err = w.BGPServer.AddPeer(context.Background(), &bgpapi.AddPeerRequest{Peer: peer})
	return err
}

func (w *PeerWatcher) updateBGPPeer(ip string, asn uint32) error {
	peer, err := w.createBGPPeer(ip, asn)
	if err != nil {
		return err
	}
	w.log.Infof("Updating BGP neighbor: %s AS:%d", peer.Conf.NeighborAddress, peer.Conf.PeerAs)
	_, err = w.BGPServer.UpdatePeer(context.Background(), &bgpapi.UpdatePeerRequest{Peer: peer})
	return err
}

func (w *PeerWatcher) deleteBGPPeer(ip string) error {
	w.log.Infof("Deleting BGP neighbor: %s", ip)
	err := w.BGPServer.DeletePeer(context.Background(), &bgpapi.DeletePeerRequest{Address: ip})
	return err
}

func (w *PeerWatcher) isMeshMode() bool {
	if w.BGPConf.NodeToNodeMeshEnabled != nil {
		return *w.BGPConf.NodeToNodeMeshEnabled
	}
	return true
}

func NewPeerWatcher(routingData *common.RoutingData, nodeWatcher *NodeWatcher, log *logrus.Entry) *PeerWatcher {
	w := PeerWatcher{
		RoutingData: routingData,
		nodeWatcher: nodeWatcher,
		nodeUpdates: nodeWatcher.NodeUpdateSubscribe(),
		log:         log,
	}
	return &w
}
