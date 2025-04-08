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

package model

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type CniServerState struct {
	Version  int                     `json:"version"`
	PodSpecs map[string]LocalPodSpec `json:"podSpecs"`
}

func NewCniServerState(podSpecs map[string]LocalPodSpec) *CniServerState {
	return &CniServerState{
		Version:  config.CniServerStateFileVersion,
		PodSpecs: podSpecs,
	}
}

func PersistCniServerState(state *CniServerState, fname string) (err error) {
	tmpFile := fmt.Sprintf("%s~", fname)
	data, err := json.Marshal(state)
	if err != nil {
		return errors.Wrap(err, "Error encoding pod data")
	}
	err = os.WriteFile(tmpFile, data, 0200)
	if err != nil {
		return errors.Wrapf(err, "Error writing file %s", tmpFile)
	}
	err = os.Rename(tmpFile, fname)
	if err != nil {
		return errors.Wrapf(err, "Error moving file %s", tmpFile)
	}
	return nil
}

func LoadCniServerState(fname string) (*CniServerState, error) {
	state := NewCniServerState(make(map[string]LocalPodSpec))
	data, err := os.ReadFile(fname)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		} else {
			return state, errors.Wrapf(err, "Error reading file %s", fname)
		}
	}
	err = json.Unmarshal(data, state)
	if err != nil {
		return state, errors.Wrapf(err, "Error unmarshaling json state")
	}
	if state.Version != config.CniServerStateFileVersion {
		// When adding new versions, we need to keep loading old versions or some pods
		// will remain disconnected forever after an upgrade
		return state, fmt.Errorf("unsupported save file version: %d", state.Version)
	}
	return state, nil
}
