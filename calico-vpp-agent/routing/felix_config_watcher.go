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
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"golang.org/x/net/context"
)

var (
	/* Not super pretty but it works... */
	lastFelixConfigurationVersion string
)

func (s *Server) GetFelixConfig() *calicov3.FelixConfigurationSpec {
	return s.felixConfiguration
}

func (s *Server) getFelixConfiguration() error {
	conf, err := s.clientv3.FelixConfigurations().Get(context.Background(), "default", options.GetOptions{})
	if err != nil {
		lastFelixConfigurationVersion = ""
		return errors.Wrap(err, "error getting default felix config")
	}
	s.handleFelixConfigurationUpdate(s.felixConfiguration, &conf.Spec)
	s.felixConfiguration = &conf.Spec
	lastFelixConfigurationVersion = conf.ResourceVersion
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
		s.getFelixConfiguration()
		watcher, err := s.clientv3.FelixConfigurations().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: lastFelixConfigurationVersion},
		)
		if err != nil {
			return err
		}
	watch:
		for update := range watcher.ResultChan() {
			switch update.Type {
			case watch.Error:
				s.log.Infof("Felix conf watch returned an error")
				break watch
			case watch.Added, watch.Modified:
				felix := update.Object.(*calicov3.FelixConfiguration)
				s.handleFelixConfigurationUpdate(s.felixConfiguration, &felix.Spec)
				s.felixConfiguration = &felix.Spec
			case watch.Deleted:
				s.log.Infof("delete while watching FelixConfigurations")
			}
		}
	}
	return nil
}
