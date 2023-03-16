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
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"
)

type BGPConfigurationWatcher struct {
	log                              *logrus.Entry
	clientv3                         calicov3cli.Interface
	BGPConfigurationWatcherEventChan chan common.CalicoVppEvent
	BGPConf                          *calicov3.BGPConfigurationSpec
}

func NewBGPConfigurationWatcher(clientv3 calicov3cli.Interface, log *logrus.Entry) *BGPConfigurationWatcher {
	w := BGPConfigurationWatcher{
		log:                              log,
		clientv3:                         clientv3,
		BGPConfigurationWatcherEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
	}
	reg := common.RegisterHandler(w.BGPConfigurationWatcherEventChan, "BGP Config watcher events")
	reg.ExpectEvents(common.BGPConfChanged)
	return &w
}

/* For now, this doesn't watch the BGP configuration nor produce events */
func (w *BGPConfigurationWatcher) GetBGPConf() (*calicov3.BGPConfigurationSpec, error) {
	defaultBGPConf, err := w.getDefaultBGPConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error getting default BGP configuration")
	}
	nodeSpecificConf, err := w.clientv3.BGPConfigurations().Get(context.Background(), "node."+config.NodeName, options.GetOptions{})
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
	b := true
	conf, err := w.clientv3.BGPConfigurations().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// Fill in nil values with default ones
		if conf.Spec.NodeToNodeMeshEnabled == nil {
			conf.Spec.NodeToNodeMeshEnabled = &b // Go is great sometimes
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
			NodeToNodeMeshEnabled: &b,
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

func (w *BGPConfigurationWatcher) WatchBGPConfiguration(t *tomb.Tomb) error {
	for t.Alive() {
		select {
		case <-t.Dying():
			return nil
		case evt := <-w.BGPConfigurationWatcherEventChan:
			switch evt.Type {
			case common.BGPConfChanged:
				oldBGPConf := w.BGPConf
				newBGPConf, err := w.GetBGPConf()
				if err != nil {
					return errors.Wrap(err, "error getting BGP configuration")
				}
				if !reflect.DeepEqual(newBGPConf, oldBGPConf) {
					w.log.Error("BGPConf updated")
					return errors.Errorf("BGPConf updated, restarting")
				}
			default:
			}
		}
	}
	return nil
}
