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
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
)

type FelixConfWatcher struct {
	log                *logrus.Entry
	felixConfiguration *calicov3.FelixConfigurationSpec
	/* Not super pretty but it works... */
	lastFelixConfigurationVersion string
	watchedFelixConfName          string
	clientv3                      calicov3cli.Interface
	watcher                       watch.Interface
}

func (w *FelixConfWatcher) getFelixConfiguration() error {
	felixConfList, err := w.clientv3.FelixConfigurations().List(context.Background(), options.ListOptions{})
	if err != nil {
		w.lastFelixConfigurationVersion = ""
		return errors.Wrap(err, "Error getting felix config")
	}
	w.lastFelixConfigurationVersion = felixConfList.ResourceVersion
	for _, felixConf := range felixConfList.Items {
		if felixConf.Name == w.watchedFelixConfName {
			w.handleFelixConfigurationUpdate(w.felixConfiguration, &felixConf.Spec)
			w.felixConfiguration = &felixConf.Spec
			return nil
		}
	}
	w.log.Warnf("Didn't find a FelixConfig named %s", w.watchedFelixConfName)
	return nil
}

func (w *FelixConfWatcher) handleFelixConfigurationUpdate(old, new *calicov3.FelixConfigurationSpec) {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.FelixConfChanged,
		Old:  old,
		New:  new,
	})
}

func (w *FelixConfWatcher) OnVppRestart() {
	/* We don't do anything */
}

func (w *FelixConfWatcher) WatchFelixConfiguration(t *tomb.Tomb) error {
	for t.Alive() {
		w.lastFelixConfigurationVersion = ""
		err := w.resyncAndCreateWatcher()
		if err != nil {
			w.log.Error(err)
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				w.log.Infof("FelixConfig Watcher asked to stop")
				w.cleanExistingWatcher()
				return nil
			case update, ok := <-w.watcher.ResultChan():
				if !ok {
					err := w.resyncAndCreateWatcher()
					if err != nil {
						w.log.Error(err)
						goto restart
					}
					continue
				}
				switch update.Type {
				case watch.Error:
					w.log.Infof("FelixConfig watch returned an error %v", update)
					goto restart
				case watch.Added, watch.Modified:
					felix := update.Object.(*calicov3.FelixConfiguration)
					w.handleFelixConfigurationUpdate(w.felixConfiguration, &felix.Spec)
					w.felixConfiguration = &felix.Spec
				case watch.Deleted:
					w.log.Infof("FelixConfig watch returned delete")
				}
			}
		}
	restart:
		w.log.Info("restarting FelixConfig watcher...")
		w.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	w.log.Infof("Felixconfig Watcher asked to stop")

	return nil
}

func (w *FelixConfWatcher) resyncAndCreateWatcher() error {
	if w.lastFelixConfigurationVersion == "" {
		err := w.getFelixConfiguration()
		if err != nil {
			return errors.Wrap(err, "Error getting initial Felix config %s")
		}
	}
	w.cleanExistingWatcher()
	felixConfigWatcher, err := w.clientv3.FelixConfigurations().Watch(
		context.Background(),
		options.ListOptions{ResourceVersion: w.lastFelixConfigurationVersion},
	)
	if err != nil {
		return err
	}
	w.watcher = felixConfigWatcher
	return nil
}

func (w *FelixConfWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.log.Info("Stopped watcher")
		w.watcher = nil
	}
}

func NewFelixConfWatcher(clientv3 calicov3cli.Interface, log *logrus.Entry) *FelixConfWatcher {
	w := FelixConfWatcher{
		log:                  log,
		clientv3:             clientv3,
		watchedFelixConfName: "default",
	}
	return &w
}
