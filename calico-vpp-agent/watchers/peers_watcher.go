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

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

// PeerWatcherHandler defines the interface for handling BGP peer updates
type PeerWatcherHandler interface {
	ProcessPeers(peers []calicov3.BGPPeer, state map[string]*common.BGPPeerState) error
	SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec)
}

type PeerWatcher struct {
	log      *logrus.Entry
	clientv3 calicov3cli.Interface

	watcher              watch.Interface
	currentWatchRevision string

	handler PeerWatcherHandler

	state map[string]*common.BGPPeerState
}

func NewPeerWatcher(clientv3 calicov3cli.Interface, handler PeerWatcherHandler, log *logrus.Entry) *PeerWatcher {
	w := &PeerWatcher{
		log:      log,
		clientv3: clientv3,
		handler:  handler,
		state:    make(map[string]*common.BGPPeerState),
	}

	return w
}

func (w *PeerWatcher) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	w.handler.SetBGPConf(bgpConf)
}

// WatchBGPPeers watches BGP peers configured in Calico and delegates processing to handler
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
			default:
				w.log.Info("Peers updated, reevaluating peerings")
				// Re-sync peers when watch events occur
				err = w.resyncPeers()
				if err != nil {
					w.log.Error(errors.Wrapf(err, "Error re-syncing peers after watch event"))
					goto restart
				}
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

	// Delegate the actual processing to the handler
	return w.handler.ProcessPeers(peers.Items, w.state)
}

func (w *PeerWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.log.Debug("Stopped watcher")
		w.watcher = nil
	}
}

// GetState returns the current peer state
func (w *PeerWatcher) GetState() map[string]*common.BGPPeerState {
	return w.state
}
