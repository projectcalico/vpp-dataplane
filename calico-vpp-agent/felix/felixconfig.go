// Copyright (C) 2025 Cisco Systems Inc.
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

package felix

import (
	"reflect"
	"regexp"

	felixConfig "github.com/projectcalico/calico/felix/config"

	"github.com/projectcalico/calico/felix/proto"
)

/**
 * remove add the fields of type `file` we dont need and for which the
 * parsing will fail
 *
 * This logic is extracted from `loadParams` in [0]
 * [0] projectcalico/felix/config/config_params.go:Config
 * it applies the regex only on the reflected struct definition,
 * not on the live data.
 *
 **/
func removeFelixConfigFileField(rawData map[string]string) {
	config := felixConfig.Config{}
	kind := reflect.TypeOf(config)
	metaRegexp := regexp.MustCompile(`^([^;(]+)(?:\(([^)]*)\))?;` +
		`([^;]*)(?:;` +
		`([^;]*))?$`)
	for ii := 0; ii < kind.NumField(); ii++ {
		field := kind.Field(ii)
		tag := field.Tag.Get("config")
		if tag == "" {
			continue
		}
		captures := metaRegexp.FindStringSubmatch(tag)
		kind := captures[1] // Type: "int|oneof|bool|port-list|..."
		if kind == "file" {
			delete(rawData, field.Name)
		}
	}
}

// the msg.Config map[string]string is the serialized object
// projectcalico/felix/config/config_params.go:Config
func (s *Server) handleConfigUpdate(msg *proto.ConfigUpdate) (err error) {
	s.log.Infof("Got config from felix: %+v", msg)

	oldFelixConfig := s.cache.FelixConfig
	removeFelixConfigFileField(msg.Config)
	s.cache.FelixConfig = felixConfig.New()
	_, err = s.cache.FelixConfig.UpdateFrom(msg.Config, felixConfig.InternalOverride)
	if err != nil {
		return err
	}
	changed := !reflect.DeepEqual(
		oldFelixConfig.RawValues(),
		s.cache.FelixConfig.RawValues(),
	)

	// Note: This function will be called each time the Felix config changes.
	// If we start handling config settings that require agent restart,
	// we'll need to add a mechanism for that
	if !s.felixConfigReceived {
		s.felixConfigReceived = true
		s.FelixConfigChan <- s.cache.FelixConfig
	}

	if !changed {
		return nil
	}

	s.cniHandler.OnFelixConfChanged(oldFelixConfig, s.cache.FelixConfig)
	s.policiesHandler.OnFelixConfChanged(oldFelixConfig, s.cache.FelixConfig)

	return nil
}
