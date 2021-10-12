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
	"github.com/projectcalico/libcalico-go/lib/watch"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type PeerWatcher struct {
	*common.RoutingData
	log *logrus.Entry

	currentCalicoNode oldv3.Node
}

type bgpPeer struct {
	AS        uint32
	SweepFlag bool
}

// SelectsNode determines whether or not the selector mySelector
// matches the labels on the given node.
func SelectsNode(mySelector string, n oldv3.Node) (bool, error) {
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
	matches, err := SelectsNode(peer.Spec.NodeSelector, w.currentCalicoNode)
	if err != nil {
		w.log.Error("Error in nodeSelector matching")
	}
	if (peer.Spec.Node != "" && peer.Spec.Node != config.NodeName) || (peer.Spec.NodeSelector != "" && !matches) {
		return false
	}
	return true
}

// Select among nodes list peers that match with peerSelector
// return corresponding ips and ASN in a map
func (w *PeerWatcher) selectPeers(nodes *oldv3.NodeList, peerSelector string) map[string]uint32 {
	ipAsn := make(map[string]uint32)
	for _, calicoNode := range nodes.Items {
		matches, err := SelectsNode(peerSelector, calicoNode)
		if err != nil {
			w.log.Error("Error in peerSelector matching")
		}
		if matches {
			if calicoNode.Spec.BGP.IPv4Address != "" && w.currentCalicoNode.Spec.BGP.IPv4Address != "" {
				ad, _, _ := net.ParseCIDR(calicoNode.Spec.BGP.IPv4Address)
				if calicoNode.Spec.BGP.ASNumber == nil {
					ipAsn[ad.String()] = uint32(*w.BGPConf.ASNumber)
				} else {
					ipAsn[ad.String()] = uint32(*calicoNode.Spec.BGP.ASNumber)
				}
			}
			if calicoNode.Spec.BGP.IPv6Address != "" && w.currentCalicoNode.Spec.BGP.IPv6Address != "" {
				ad, _, _ := net.ParseCIDR(calicoNode.Spec.BGP.IPv6Address)
				if calicoNode.Spec.BGP.ASNumber == nil {
					ipAsn[ad.String()] = uint32(*w.BGPConf.ASNumber)
				} else {
					ipAsn[ad.String()] = uint32(*calicoNode.Spec.BGP.ASNumber)
				}
			}
		}
	}
	return ipAsn
}

// This function watches BGP peers configured in Calico
// These peers are configured in GoBGP in adcition to the other nodes in the cluster
func (w *PeerWatcher) WatchBGPPeers() error {
	state := make(map[string]*bgpPeer)

	for {
		w.log.Debugf("Reconciliating peers...")
		peers, err := w.Clientv3.BGPPeers().List(context.Background(), options.ListOptions{})
		if err != nil {
			return err
		}
		nodes, err := w.Clientv3.Nodes().List(context.Background(), options.ListOptions{})
		if err != nil {
			return err
		}
		for _, node := range nodes.Items {
			if node.Name == config.NodeName {
				w.currentCalicoNode = node
			}
		}
		for _, p := range state {
			p.SweepFlag = true
		}
		for _, peer := range peers.Items {
			if !w.shouldPeer(&peer) {
				continue
			}
			ip := peer.Spec.PeerIP
			asn := uint32(peer.Spec.ASNumber)
			peerSelector := peer.Spec.PeerSelector
			ipAsn := make(map[string]uint32)
			if peerSelector != "" {
				// use peerSelector
				ipAsn = w.selectPeers(nodes, peerSelector)
			} else {
				// use peerIP and ASNumber
				ipAsn[ip] = asn
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
	watch:
		for update := range watcher.ResultChan() {
			switch update.Type {
			case watch.Added, watch.Modified:
				peer := update.Object.(*calicov3.BGPPeer)
				if !w.shouldPeer(peer) {
					continue
				}
				ip := peer.Spec.PeerIP
				asn := uint32(peer.Spec.ASNumber)
				peerSelector := peer.Spec.PeerSelector
				ipAsn := make(map[string]uint32)
				if peerSelector != "" {
					ipAsn = w.selectPeers(nodes, peerSelector)
				} else {
					ipAsn[ip] = asn
				}
				existing, ok := state[ip]
				for ip, asn := range ipAsn {
					if ok {
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
			case watch.Deleted:
				peer := update.Previous.(*calicov3.BGPPeer)
				if !w.shouldPeer(peer) {
					continue
				}
				ip := peer.Spec.PeerIP
				peerSelector := peer.Spec.PeerSelector
				ipAsn := make(map[string]uint32)
				if peerSelector != "" {
					ipAsn = w.selectPeers(nodes, peerSelector)
				} else {
					ipAsn[ip] = 0
				}
				for ip := range ipAsn {
					_, ok := state[ip]
					if !ok {
						w.log.Warnf("Deleted peer %s not found", ip)
						continue
					}
					err := w.deleteBGPPeer(ip)
					if err != nil {
						return errors.Wrap(err, "error deleting BGP peer")
					}
					delete(state, ip)
				}
			case watch.Error:
				w.log.Infof("peers watch returned an error")
				break watch
			}
		}
	}
	return nil
}

func (w *PeerWatcher) createBGPPeer(ip string, asn uint32) (*bgpapi.Peer, error) {
	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, err
	}
	typ := &common.BgpFamilyUnicastIPv4
	if ipAddr.IP.To4() == nil {
		typ = &common.BgpFamilyUnicastIPv6
	}

	afiSafis := []*bgpapi.AfiSafi{
		&bgpapi.AfiSafi{
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

func NewPeerWatcher(routingData *common.RoutingData, log *logrus.Entry) *PeerWatcher {
	w := PeerWatcher{
		RoutingData: routingData,
		log:         log,
	}
	return &w
}
