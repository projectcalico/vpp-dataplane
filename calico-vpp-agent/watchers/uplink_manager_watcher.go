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
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type UplinkManagerWatcher struct {
	log               *log.Entry
	usr2SignalChannel chan os.Signal
}

func NewUplinkManagerWatcher(usr2SignalChannel chan os.Signal, log *log.Entry) *UplinkManagerWatcher {
	return &UplinkManagerWatcher{
		usr2SignalChannel: usr2SignalChannel,
		log:               log,
	}
}

func (w *UplinkManagerWatcher) WatchUplinks(t *tomb.Tomb) error {
	for t.Alive() {
		<-w.usr2SignalChannel
		/* vpp-manager pokes us with USR2 if status changes (dynamically added interface) */
		w.log.Info("Vpp manager state changed")
		dat, err := os.ReadFile(config.VppManagerInfoFile)
		if err != nil {
			w.log.Error(err)
		} else {
			err2 := json.Unmarshal(dat, common.VppManagerInfo)
			if err2 != nil {
				w.log.Error(errors.Errorf("cannot unmarshal vpp manager info file %s", err2))
			} else if common.VppManagerInfo.Status == config.Ready {
				w.log.Info("local vppmanager state updated")
				common.SendEvent(common.CalicoVppEvent{
					Type: common.UplinksUpdated,
				})
			} else {
				w.log.Error(errors.Errorf("vpp manager file status not ready after dynamically added interface"))
			}
		}
	}
	return nil
}
