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
	"time"

	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	tomb "gopkg.in/tomb.v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/config"
)

type PeerWatcher struct {
	log      *logrus.Entry
	clientv3 calicov3cli.Interface

	// Subcomponent for accessing and watching secrets (that hold BGP passwords).
	secretWatcher *secretWatcher

	nodeStatesByName     map[string]oldv3.Node
	peerWatcherEventChan chan common.CalicoVppEvent
	BGPConf              *calicov3.BGPConfigurationSpec
	watcher              watch.Interface
	currentWatchRevision string
}

type bgpPeer struct {
	AS            uint32
	SweepFlag     bool
	BGPPeerSpec   *calicov3.BGPPeerSpec
	SecretChanged bool
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
	matches, err := selectsNode(peer.Spec.NodeSelector, w.currentCalicoNode())
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
func (w *PeerWatcher) selectPeers(peerSelector string) map[string]uint32 {
	ipAsn := make(map[string]uint32)
	for _, node := range w.nodeStatesByName {
		if node.Name == config.NodeName {
			continue // Don't peer with ourselves :)
		}
		matches, err := selectsNode(peerSelector, &node)
		if err != nil {
			w.log.Errorf("Error in peerSelector matching: %v", err)
		}
		if matches {
			if node.Spec.BGP != nil && node.Spec.BGP.IPv4Address != "" &&
				w.currentCalicoNode().Spec.BGP != nil &&
				w.currentCalicoNode().Spec.BGP.IPv4Address != "" {
				ad, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
				if err == nil {
					ipAsn[ad.String()] = w.getAsNumber(&node)
				} else {
					w.log.Warnf("Can't parse node IPv4: %s", node.Spec.BGP.IPv4Address)
				}
			}
			if node.Spec.BGP != nil && node.Spec.BGP.IPv6Address != "" &&
				w.currentCalicoNode().Spec.BGP != nil &&
				w.currentCalicoNode().Spec.BGP.IPv6Address != "" {
				ad, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
				if err == nil {
					ipAsn[ad.String()] = w.getAsNumber(&node)
				} else {
					w.log.Warnf("Can't parse node IPv6: %s", node.Spec.BGP.IPv6Address)
				}
			}
		}
	}
	return ipAsn
}

func (w *PeerWatcher) currentCalicoNode() *oldv3.Node {
	node := w.nodeStatesByName[config.NodeName]
	return &node
}

// This function watches BGP peers configured in Calico
// These peers are configured in GoBGP in addition to the other nodes in the cluster
// They may also control which nodes to pair with if the peerSelector is set
func (w *PeerWatcher) WatchBGPPeers(t *tomb.Tomb) error {
	w.log.Infof("PEER watcher starts")
	state := make(map[string]*bgpPeer)
	for t.Alive() {
		w.currentWatchRevision = ""
		err := w.resyncAndCreateWatcher(state)
		if err != nil {
			w.log.Error(err)
			goto restart
		}
		// node and peer updates should be infrequent enough so just reevaluate
		// all peerings everytime there is an update.
		select {
		case <-t.Dying():
			w.log.Infof("Peers Watcher asked to stop")
			w.cleanExistingWatcher()
			return nil
		case event, ok := <-w.watcher.ResultChan():
			if !ok {
				err := w.resyncAndCreateWatcher(state)
				if err != nil {
					goto restart
				}
				continue
			}
			switch event.Type {
			case watch.EventType(api.WatchError):
				w.log.Debug("peers watch returned, restarting...")
				goto restart
			default:
				w.log.Info("Peers updated, reevaluating peerings")
			}
		case evt := <-w.peerWatcherEventChan:
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.PeerNodeStateChanged:
				old, _ := evt.Old.(*oldv3.Node)
				new, _ := evt.New.(*oldv3.Node)
				if old != nil {
					delete(w.nodeStatesByName, old.Name)
				}
				if new != nil {
					w.nodeStatesByName[new.Name] = *new
				}
				w.log.Debugf("Nodes updated, reevaluating peerings old %v new %v", old, new)
			case common.BGPSecretChanged:
				old, _ := evt.Old.(*v1.Secret)
				new, _ := evt.New.(*v1.Secret)
				secretEvt := ""
				secretName := ""
				// secret added
				if old == nil && new != nil {
					secretEvt = "add"
					secretName = new.Name
					w.log.Infof("New secret '%s' added", new.Name)
				}
				// secret deleted
				if old != nil && new == nil {
					secretEvt = "del"
					secretName = old.Name
					w.log.Infof("secret '%s' deleted", old.Name)
				}
				// secret updated
				if old != nil && new != nil {
					secretEvt = "upd"
					secretName = old.Name
					w.log.Infof("secret '%s' updated", old.Name)
				}
				// sweep through the peers and update the SecretChanged field of impacted peers
				for _, peer := range state {
					switch secretEvt {
					case "add":
						// Note: any future add event specifc processing code goes here. For now we fallthrough.
						fallthrough
					case "del":
						// Note: any future delete event specifc processing code goes here. For now we fallthrough.
						fallthrough
					case "upd":
						// BGP password has changed
						if w.getSecretName(peer.BGPPeerSpec) == secretName {
							w.log.Infof("SecretChanged field set for peer=%s", peer.BGPPeerSpec.PeerIP)
							peer.SecretChanged = true
						}
					default:
						w.log.Warn("Unrecognized secret change event received. Ignoring...")
					}
				}
			default:
				goto restart
			}
		}

	restart:
		w.log.Debug("restarting peers watcher...")
		w.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	return nil
}

func (w *PeerWatcher) resyncAndCreateWatcher(state map[string]*bgpPeer) error {
	if w.currentWatchRevision == "" {
		w.log.Debugf("Reconciliating peers...")
		peers, err := w.clientv3.BGPPeers().List(context.Background(), options.ListOptions{
			ResourceVersion: w.currentWatchRevision,
		})
		if err != nil {
			return errors.Wrap(err, "cannot list bgp peers")
		}
		w.currentWatchRevision = peers.ResourceVersion
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
		// Intialize the set consisting of active secrets
		activeSecrets := map[string]struct{}{}
		for _, peer := range peers.Items {
			if !w.shouldPeer(&peer) {
				continue
			}
			ipAsn := make(map[string]uint32)
			if peer.Spec.PeerSelector != "" {
				// this peer has a peerSelector, use it
				ipAsn = w.selectPeers(peer.Spec.PeerSelector)
			} else {
				// use peerIP and ASNumber specified in the peer
				ipAsn[peer.Spec.PeerIP] = uint32(peer.Spec.ASNumber)
			}
			for ip, asn := range ipAsn {
				existing, ok := state[ip]
				if ok {
					w.log.Debugf("peer(update) neighbor ip=%s for BGPPeer=%s", ip, peer.ObjectMeta.Name)
					existing.SweepFlag = false
					oldSecret := w.getSecretName(existing.BGPPeerSpec)
					newSecret := w.getSecretName(&peer.Spec)
					w.log.Debugf("peer(update) oldSecret=%s newSecret=%s SecretChanged=%t for BGPPeer=%s", oldSecret, newSecret, existing.SecretChanged, peer.ObjectMeta.Name)
					if existing.AS != asn || oldSecret != newSecret || existing.SecretChanged {
						err := w.updateBGPPeer(ip, asn, &peer.Spec)
						if err != nil {
							w.log.Warn(errors.Wrapf(err, "error updating BGP peer %s, ip=%s", peer.ObjectMeta.Name, ip))
							continue
						}
						existing.AS = asn
						existing.BGPPeerSpec = peer.Spec.DeepCopy()
						existing.SecretChanged = false
					} // Else no change, nothing to do
				} else {
					// New peer
					w.log.Infof("peer(add) neighbor ip=%s for BGPPeer=%s", ip, peer.ObjectMeta.Name)
					err := w.addBGPPeer(ip, asn, &peer.Spec)
					if err != nil {
						w.log.Warn(errors.Wrapf(err, "error adding BGP peer %s, ip=%s", peer.ObjectMeta.Name, ip))
						// Add the secret to the set of active secrets so it does not get cleaned up
						secretName := w.getSecretName(&peer.Spec)
						if secretName != "" {
							activeSecrets[secretName] = struct{}{}
						}
						continue
					}
					state[ip] = &bgpPeer{
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
				w.log.Infof("peer(del) neighbor ip=%s", ip)
				err := w.deleteBGPPeer(ip)
				if err != nil {
					w.log.Warn(errors.Wrapf(err, "error deleting BGP peer %s", ip))
				}
				delete(state, ip)
			}
		}
		// Clean up any secrets that are no longer referenced by any bgp peers
		for _, peer := range state {
			secretName := w.getSecretName(peer.BGPPeerSpec)
			if secretName != "" {
				activeSecrets[secretName] = struct{}{}
			}
		}
		w.secretWatcher.SweepStale(activeSecrets)
	}
	w.cleanExistingWatcher()
	watcher, err := w.clientv3.BGPPeers().Watch(
		context.Background(),
		options.ListOptions{ResourceVersion: w.currentWatchRevision},
	)
	if err != nil {
		return err
	}
	w.watcher = watcher
	return nil
}

func (w *PeerWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.log.Debug("Stopped watcher")
		w.watcher = nil
	}
}

func (w *PeerWatcher) createBGPPeer(ip string, asn uint32, peerSpec *calicov3.BGPPeerSpec) (*bgpapi.Peer, error) {
	w.log.Infof("createBGPPeer with ip %s", ip)
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

	if w.getSecretKeyRef(peerSpec) != nil {
		peer.Conf.AuthPassword, err = w.getPassword(peerSpec.Password.SecretKeyRef)
		if err != nil {
			return nil, err
		}
	}
	return peer, nil
}

func (w *PeerWatcher) addBGPPeer(ip string, asn uint32, peerSpec *calicov3.BGPPeerSpec) error {
	peer, err := w.createBGPPeer(ip, asn, peerSpec)
	if err != nil {
		return errors.Wrap(err, "cannot add bgp peer")
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerAdded,
		New:  peer,
	})
	return nil
}

func (w *PeerWatcher) updateBGPPeer(ip string, asn uint32, peerSpec *calicov3.BGPPeerSpec) error {
	peer, err := w.createBGPPeer(ip, asn, peerSpec)
	if err != nil {
		return errors.Wrap(err, "cannot update bgp peer")
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerUpdated,
		New:  peer,
	})
	return nil
}

func (w *PeerWatcher) deleteBGPPeer(ip string) error {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPPeerDeleted,
		New:  ip,
	})
	return nil
}

func (w *PeerWatcher) isMeshMode() bool {
	if w.BGPConf.NodeToNodeMeshEnabled != nil {
		return *w.BGPConf.NodeToNodeMeshEnabled
	}
	return true
}

func (w *PeerWatcher) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	w.BGPConf = bgpConf
}

// Given peer's BGPPeerConf check if Password is set and return SecretKeyRef
func (w *PeerWatcher) getSecretKeyRef(spec *calicov3.BGPPeerSpec) *v1.SecretKeySelector {
	if spec.Password != nil && spec.Password.SecretKeyRef != nil {
		return spec.Password.SecretKeyRef
	}
	return nil
}

// Given peer's BGPPeerConf check if Password is set and return secret name
func (w *PeerWatcher) getSecretName(spec *calicov3.BGPPeerSpec) string {
	if spec.Password != nil && spec.Password.SecretKeyRef != nil {
		return spec.Password.SecretKeyRef.Name
	}
	return ""
}

// Get the BGP password from SecretWatcher
func (w *PeerWatcher) getPassword(secretKeySelector *v1.SecretKeySelector) (string, error) {
	password, err := w.secretWatcher.GetSecret(
		secretKeySelector.Name,
		secretKeySelector.Key,
	)
	return password, err
}

// This function gets called from SecretWatcher when a secret is added, updated or deleted
func (w *PeerWatcher) OnSecretUpdate(old, new *v1.Secret) {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPSecretChanged,
		Old:  old,
		New:  new,
	})
}

func NewPeerWatcher(clientv3 calicov3cli.Interface, k8sclient *kubernetes.Clientset, log *logrus.Entry) *PeerWatcher {
	var err error
	w := PeerWatcher{
		clientv3:             clientv3,
		nodeStatesByName:     make(map[string]oldv3.Node),
		log:                  log,
		peerWatcherEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
	}
	w.secretWatcher, err = NewSecretWatcher(&w, k8sclient)
	if err != nil {
		log.Fatalf("NewSecretWatcher failed with %s", err)
	}
	reg := common.RegisterHandler(w.peerWatcherEventChan, "peers watcher events")
	reg.ExpectEvents(common.PeerNodeStateChanged, common.BGPSecretChanged)

	return &w
}
