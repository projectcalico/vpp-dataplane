// Copyright (C) 2021 Cisco Systems Inc.
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
	"reflect"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	calicoerr "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type BGPConfigurationWatcher struct {
	log      *logrus.Entry
	clientv3 calicov3cli.Interface
	BGPConf  *calicov3.BGPConfigurationSpec
	// Watch interface for monitoring BGP configuration changes
	watcher              watch.Interface
	currentWatchRevision string
	// Callback function to handle BGP configuration changes
	onBGPConfigChanged func() error
}

func NewBGPConfigurationWatcher(clientv3 calicov3cli.Interface, log *logrus.Entry, configChangeHandler func() error) *BGPConfigurationWatcher {
	w := BGPConfigurationWatcher{
		log:                log,
		clientv3:           clientv3,
		onBGPConfigChanged: configChangeHandler,
	}
	return &w
}

/* For now, this doesn't watch the BGP configuration nor produce events */
func (w *BGPConfigurationWatcher) GetBGPConf() (*calicov3.BGPConfigurationSpec, error) {
	defaultBGPConf, err := w.getDefaultBGPConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error getting default BGP configuration")
	}
	nodeSpecificConf, err := w.clientv3.BGPConfigurations().Get(context.Background(), "node."+*config.NodeName, options.GetOptions{})
	if err != nil {
		switch err.(type) {
		case calicoerr.ErrorResourceDoesNotExist:
			w.BGPConf = defaultBGPConf
			return defaultBGPConf, nil
		default:
			return nil, errors.Wrap(err, "error getting node specific BGP configurations")
		}
	}
	if nodeSpecificConf.Spec.ListenPort != 0 {
		defaultBGPConf.ListenPort = nodeSpecificConf.Spec.ListenPort
	}
	if defaultBGPConf.LogSeverityScreen != "" {
		defaultBGPConf.LogSeverityScreen = nodeSpecificConf.Spec.LogSeverityScreen
	}
	w.BGPConf = defaultBGPConf
	return defaultBGPConf, nil
}

func (w *BGPConfigurationWatcher) getDefaultBGPConfig() (*calicov3.BGPConfigurationSpec, error) {
	conf, err := w.clientv3.BGPConfigurations().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// Fill in nil values with default ones
		if conf.Spec.NodeToNodeMeshEnabled == nil {
			conf.Spec.NodeToNodeMeshEnabled = &config.True // Go is great sometimes
		}
		if conf.Spec.ASNumber == nil {
			asn, err := numorstring.ASNumberFromString("64512")
			if err != nil {
				return nil, err
			}
			conf.Spec.ASNumber = &asn
		}
		if conf.Spec.ListenPort == 0 {
			conf.Spec.ListenPort = 179
		}
		if conf.Spec.LogSeverityScreen == "" {
			conf.Spec.LogSeverityScreen = "Info"
		}
		if conf.Spec.ServiceClusterIPs == nil {
			conf.Spec.ServiceClusterIPs = []calicov3.ServiceClusterIPBlock{}
		}
		if conf.Spec.ServiceExternalIPs == nil {
			conf.Spec.ServiceExternalIPs = []calicov3.ServiceExternalIPBlock{}
		}
		if conf.Spec.ServiceLoadBalancerIPs == nil {
			conf.Spec.ServiceLoadBalancerIPs = []calicov3.ServiceLoadBalancerIPBlock{}
		}
		return &conf.Spec, nil
	}
	switch err.(type) {
	case calicoerr.ErrorResourceDoesNotExist:
		w.log.Debug("No default BGP config found, using default options")
		ret := &calicov3.BGPConfigurationSpec{
			LogSeverityScreen:     "Info",
			NodeToNodeMeshEnabled: &config.True,
			ListenPort:            179,
		}
		asn, err := numorstring.ASNumberFromString("64512")
		if err != nil {
			return nil, err
		}
		ret.ASNumber = &asn
		return ret, nil
	default:
		return nil, err
	}
}

// WatchBGPConfiguration watches for changes in BGP configuration using Calico API
func (w *BGPConfigurationWatcher) WatchBGPConfiguration(t *tomb.Tomb) error {
	w.log.Info("BGP configuration watcher started")
	for t.Alive() {
		w.currentWatchRevision = ""
		err := w.resyncAndCreateWatcher()
		if err != nil {
			w.log.WithError(err).Error("Failed to create BGP configuration watcher")
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				w.log.Info("BGP configuration watcher asked to stop")
				w.cleanExistingWatcher()
				return nil
			case event, ok := <-w.watcher.ResultChan():
				if !ok {
					w.log.Debug("BGP configuration watcher closed, restarting...")
					goto restart
				}
				w.currentWatchRevision = event.Object.(*calicov3.BGPConfiguration).GetResourceVersion()
				switch event.Type {
				case watch.Error:
					w.log.Debug("BGP configuration watch returned error, restarting...")
					goto restart
				case watch.Added, watch.Modified:
					w.handleBGPConfigurationUpdate()
				case watch.Deleted:
					w.log.Debug("BGP configuration deleted, using defaults")
					w.handleBGPConfigurationUpdate()
				}
			}
		}
	restart:
		w.cleanExistingWatcher()
		w.log.Debug("Restarting BGP configuration watcher...")
	}
	return nil
}

// resyncAndCreateWatcher creates a new watcher for BGP configurations
func (w *BGPConfigurationWatcher) resyncAndCreateWatcher() error {
	w.cleanExistingWatcher()

	opts := options.ListOptions{
		ResourceVersion: w.currentWatchRevision,
	}

	watcher, err := w.clientv3.BGPConfigurations().Watch(context.Background(), opts)
	if err != nil {
		return errors.Wrap(err, "failed to create BGP configuration watcher")
	}
	w.watcher = watcher
	return nil
}

// cleanExistingWatcher closes the existing watcher if it exists
func (w *BGPConfigurationWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.watcher = nil
	}
}

// handleBGPConfigurationUpdate handles BGP configuration update events
func (w *BGPConfigurationWatcher) handleBGPConfigurationUpdate() {
	if w.onBGPConfigChanged == nil {
		w.log.Debug("No BGP configuration change handler set")
		return
	}

	oldConf := w.BGPConf
	newConf, err := w.GetBGPConf()
	if err != nil {
		w.log.WithError(err).Error("Failed to get updated BGP configuration")
		return
	}

	// Only call the callback if the config actually changed
	if !reflect.DeepEqual(oldConf, newConf) {
		if err := w.onBGPConfigChanged(); err != nil {
			w.log.WithError(err).Error("BGP configuration change handler failed")
		}
	}
}
