// Copyright (C) 2023 Cisco Systems Inc.
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
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"k8s.io/client-go/kubernetes"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

type BGPFilterWatcher struct {
	log                  *logrus.Entry
	clientv3             calicov3cli.Interface
	watcher              watch.Interface
	currentWatchRevision string
}

// This function watches BGPFilters configured in Calico
func (w *BGPFilterWatcher) WatchBGPFilters(t *tomb.Tomb) error {
	w.log.Infof("BGPFilter watcher starts")
	for t.Alive() {
		w.currentWatchRevision = ""
		err := w.resyncAndCreateWatcher()
		if err != nil {
			w.log.Error(err)
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				w.log.Infof("BGPFilter Watcher asked to stop")
				w.cleanExistingWatcher()
				return nil
			case event, ok := <-w.watcher.ResultChan():
				if !ok {
					err := w.resyncAndCreateWatcher()
					if err != nil {
						w.log.Error(err)
						goto restart
					}
					continue
				}
				switch event.Type {
				case watch.EventType(api.WatchError):
					w.log.Debug("BGPFilter watch returned, restarting...")
					goto restart
				case watch.EventType(api.WatchModified):
					filter, ok := event.Object.(*calicov3.BGPFilter)
					if !ok || filter == nil {
						w.log.Fatal("api.WatchModified Object is not BGPFilter or is nil")
					}
					w.UpdateFilter(*filter)
				case watch.EventType(api.WatchAdded):
					filter, ok := event.Object.(*calicov3.BGPFilter)
					if !ok || filter == nil {
						w.log.Fatal("api.WatchAdded	 Object is not BGPFilter or is nil")
					}
					w.AddNewFilter(*filter)
				case watch.EventType(api.WatchDeleted):
					filter, ok := event.Previous.(*calicov3.BGPFilter)
					if !ok || filter == nil {
						w.log.Fatal("api.WatchDeleted Previous is not BGPFilter or is nil")
					}
					w.RemoveFilter(*filter)
				}
			}
		}

	restart:
		w.log.Debug("restarting BGPFilter watcher...")
		w.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	w.log.Warn("BGPFilter watcher stopped")
	return nil
}

func (w *BGPFilterWatcher) AddNewFilter(filter calicov3.BGPFilter) {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPFilterAddedOrUpdated,
		New:  filter,
	})
}

func (w *BGPFilterWatcher) UpdateFilter(filter calicov3.BGPFilter) {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPFilterAddedOrUpdated,
		New:  filter,
	})
}

func (w *BGPFilterWatcher) RemoveFilter(filter calicov3.BGPFilter) {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPFilterDeleted,
		Old:  filter,
	})
}

func (w *BGPFilterWatcher) resyncAndCreateWatcher() error {
	if w.currentWatchRevision == "" {
		w.log.Debugf("Reconciliating BGPFilters...")
		BGPFilters, err := w.clientv3.BGPFilter().List(context.Background(), options.ListOptions{
			ResourceVersion: w.currentWatchRevision,
		})
		if err != nil {
			return errors.Wrap(err, "cannot list BGPFilters")
		}
		for _, filter := range BGPFilters.Items {
			w.AddNewFilter(filter)
		}
		w.currentWatchRevision = BGPFilters.ResourceVersion
	}
	w.cleanExistingWatcher()
	watcher, err := w.clientv3.BGPFilter().Watch(
		context.Background(),
		options.ListOptions{ResourceVersion: w.currentWatchRevision},
	)
	if err != nil {
		return err
	}
	w.watcher = watcher
	return nil
}

func (w *BGPFilterWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.log.Debug("Stopped watcher")
		w.watcher = nil
	}
}

func NewBGPFilterWatcher(clientv3 calicov3cli.Interface, k8sclient *kubernetes.Clientset, log *logrus.Entry) *BGPFilterWatcher {
	w := BGPFilterWatcher{
		clientv3: clientv3,
		log:      log,
	}
	return &w
}
