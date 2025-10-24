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
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"
	"k8s.io/client-go/kubernetes"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

type PeerWatcher struct {
	log      *logrus.Entry
	clientv3 calicov3cli.Interface

	watcher              watch.Interface
	currentWatchRevision string

	secretWatcher *secretWatcher
	cachedPeers   map[string]calicov3.BGPPeer // name -> peer
}

func NewPeerWatcher(clientv3 calicov3cli.Interface, k8sclient *kubernetes.Clientset, log *logrus.Entry) *PeerWatcher {
	w := &PeerWatcher{
		log:           log,
		clientv3:      clientv3,
		secretWatcher: NewSecretWatcher(k8sclient),
		cachedPeers:   make(map[string]calicov3.BGPPeer),
	}

	return w
}

// WatchBGPPeers watches BGP peers configured in Calico and emits granular events
func (w *PeerWatcher) WatchBGPPeers(t *tomb.Tomb) error {
	w.log.Infof("PEER watcher starts")
	for t.Alive() {
		w.currentWatchRevision = ""
		err := w.resyncAndCreateWatcher()
		if err != nil {
			w.log.Error(err)
			goto restart
		}

		select {
		case <-t.Dying():
			w.log.Infof("Peers Watcher asked to stop")
			w.cleanExistingWatcher()
			return nil
		case event, ok := <-w.watcher.ResultChan():
			if !ok {
				err := w.resyncAndCreateWatcher()
				if err != nil {
					goto restart
				}
				continue
			}
			switch event.Type {
			case watch.EventType(api.WatchError):
				w.log.Debug("peers watch returned, restarting...")
				goto restart
			case watch.Added:
				peer := event.Object.(*calicov3.BGPPeer)
				w.log.Infof("Peer added: %s", peer.Name)
				w.cachedPeers[peer.Name] = *peer
				w.updateSecretWatcher()
				common.SendEvent(common.CalicoVppEvent{
					Type: common.PeerAdded,
					New:  &common.PeerAddedEvent{Peer: *peer},
				})
			case watch.Modified:
				peer := event.Object.(*calicov3.BGPPeer)
				w.log.Infof("Peer updated: %s", peer.Name)
				old := w.cachedPeers[peer.Name]
				w.cachedPeers[peer.Name] = *peer
				w.updateSecretWatcher()
				common.SendEvent(common.CalicoVppEvent{
					Type: common.PeerUpdated,
					New:  &common.PeerUpdatedEvent{Old: old, New: *peer},
				})
			case watch.Deleted:
				peer := event.Previous.(*calicov3.BGPPeer)
				w.log.Infof("Peer deleted: %s", peer.Name)
				delete(w.cachedPeers, peer.Name)
				w.updateSecretWatcher()
				common.SendEvent(common.CalicoVppEvent{
					Type: common.PeerDeleted,
					New:  &common.PeerDeletedEvent{Peer: *peer},
				})
			default:
				w.log.Warnf("Unknown watch event type: %v", event.Type)
			}
		}

	restart:
		w.log.Debug("restarting peers watcher...")
		w.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	w.log.Warn("BGPPeer watcher stopped")
	return nil
}

func (w *PeerWatcher) resyncAndCreateWatcher() error {
	if w.currentWatchRevision == "" {
		err := w.resyncPeers()
		if err != nil {
			return err
		}
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

func (w *PeerWatcher) resyncPeers() error {
	w.log.Debugf("Reconciliating peers...")
	peers, err := w.clientv3.BGPPeers().List(context.Background(), options.ListOptions{
		ResourceVersion: w.currentWatchRevision,
	})
	if err != nil {
		return errors.Wrap(err, "cannot list bgp peers")
	}
	w.currentWatchRevision = peers.ResourceVersion

	// Update local cache
	w.cachedPeers = make(map[string]calicov3.BGPPeer)
	for _, peer := range peers.Items {
		w.cachedPeers[peer.Name] = peer
	}

	// Update secret watcher with current peer list
	w.updateSecretWatcher()

	// Emit event for initial peer list processing
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeersChanged,
		New:  &common.PeersChangedEvent{Peers: peers.Items},
	})

	return nil
}

// updateSecretWatcher updates the secret watcher with the current peer list
func (w *PeerWatcher) updateSecretWatcher() {
	peers := make([]calicov3.BGPPeer, 0, len(w.cachedPeers))
	for _, peer := range w.cachedPeers {
		peers = append(peers, peer)
	}
	w.secretWatcher.OnPeerListUpdated(peers)
}

func (w *PeerWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.log.Debug("Stopped watcher")
		w.watcher = nil
	}
}
