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
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type FelixConfWatcher struct {
	*common.RoutingData
	log                *logrus.Entry
	felixConfiguration *calicov3.FelixConfigurationSpec
	/* Not super pretty but it works... */
	lastFelixConfigurationVersion string
	watchedFelixConfName          string
}

func (w *FelixConfWatcher) GetFelixConfig() *calicov3.FelixConfigurationSpec {
	return w.felixConfiguration
}

func (w *FelixConfWatcher) GetFelixConfiguration() error {
	felixConfList, err := w.Clientv3.FelixConfigurations().List(context.Background(), options.ListOptions{})
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
	w.ConnectivityEventChan <- common.ConnectivityEvent{
		Type: common.FelixConfChanged,
		Old:  old,
		New:  new,
	}
}

func (w *FelixConfWatcher) WatchFelixConfiguration() error {
	for {
		var felixConfigWatcher watch.Interface = nil
		var eventChannel <-chan watch.Event = nil
		err := w.GetFelixConfiguration()
		if err != nil {
			w.log.Errorf("Error getting initial Felix config %s", err)
			goto restart
		}
		felixConfigWatcher, err = w.Clientv3.FelixConfigurations().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: w.lastFelixConfigurationVersion},
		)
		if err != nil {
			return err
			goto restart
		}
		eventChannel = felixConfigWatcher.ResultChan()
		for {
			update, ok := <-eventChannel
			if !ok {
				eventChannel = nil
				goto restart
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
	restart:
		w.log.Info("restarting FelixConfig watcher...")
		if felixConfigWatcher != nil {
			felixConfigWatcher.Stop()
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func NewFelixConfWatcher(routingData *common.RoutingData, log *logrus.Entry) *FelixConfWatcher {
	w := FelixConfWatcher{
		RoutingData:          routingData,
		log:                  log,
		watchedFelixConfName: "default",
	}
	return &w
}
