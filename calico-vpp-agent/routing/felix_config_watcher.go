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

package routing

import (
	"time"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"golang.org/x/net/context"
)

var (
	/* Not super pretty but it works... */
	lastFelixConfigurationVersion string
	watchedFelixConfName          string = "default"
)

func (s *Server) GetFelixConfig() *calicov3.FelixConfigurationSpec {
	return s.felixConfiguration
}

func (s *Server) getFelixConfiguration() error {
	felixConfList, err := s.clientv3.FelixConfigurations().List(context.Background(), options.ListOptions{})
	if err != nil {
		lastFelixConfigurationVersion = ""
		return errors.Wrap(err, "Error getting felix config")
	}
	lastFelixConfigurationVersion = felixConfList.ResourceVersion
	for _, felixConf := range felixConfList.Items {
		if felixConf.Name == watchedFelixConfName {
			s.handleFelixConfigurationUpdate(s.felixConfiguration, &felixConf.Spec)
			s.felixConfiguration = &felixConf.Spec
			return nil
		}
	}
	s.log.Warnf("Didn't find a FelixConfig named %s", watchedFelixConfName)
	return nil
}

func (s *Server) handleFelixConfigurationUpdate(old, new *calicov3.FelixConfigurationSpec) {
	if old == nil || new == nil {
		/* First/last update, do nothing*/
		return
	}
	if old.WireguardEnabled != new.WireguardEnabled {
		s.log.Infof("WireguardEnabled CHANGED !")
		s.updateAllIPConnectivity()
	} else if old.WireguardListeningPort != new.WireguardListeningPort {
		s.updateAllIPConnectivity()
	}
}

func (s *Server) watchFelixConfiguration() error {
	for {
		var felixConfigWatcher watch.Interface = nil
		var eventChannel <-chan watch.Event = nil
		err := s.getFelixConfiguration()
		if err != nil {
			s.log.Errorf("Error getting initial Felix config %s", err)
			goto restart
		}
		felixConfigWatcher, err = s.clientv3.FelixConfigurations().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: lastFelixConfigurationVersion},
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
				s.log.Infof("FelixConfig watch returned an error %v", update)
				goto restart
			case watch.Added, watch.Modified:
				felix := update.Object.(*calicov3.FelixConfiguration)
				s.handleFelixConfigurationUpdate(s.felixConfiguration, &felix.Spec)
				s.felixConfiguration = &felix.Spec
			case watch.Deleted:
				s.log.Infof("FelixConfig watch returned delete")
			}
		}
	restart:
		s.log.Info("restarting FelixConfig watcher...")
		if felixConfigWatcher != nil {
			felixConfigWatcher.Stop()
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}
