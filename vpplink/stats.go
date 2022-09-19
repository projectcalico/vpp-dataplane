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

package vpplink

import (
	"fmt"

	"github.com/pkg/errors"
	interfaces "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface"
	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
)

func GetInterfaceStats(sc *statsclient.StatsClient) (ifNames adapter.NameStat, dumpStats []adapter.StatEntry, err error) {

	dumpStatsNames, err := sc.DumpStats("/if/names")
	if err != nil {
		return nil, nil, errors.Wrapf(err, "dump stats failed")
	}
	if len(dumpStatsNames) == 0 {
		return nil, nil, errors.Wrap(err, "no interfaces available")
	}
	ifNames = dumpStatsNames[0].Data.(adapter.NameStat)

	dumpStats, err = sc.DumpStats("/if/")
	if err != nil {
		return nil, nil, errors.Wrapf(err, "dump stats failed")
	}
	return ifNames, dumpStats, nil
}

func (v *VppLink) GetBufferStats() (uint32, uint32, uint32, error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &interfaces.GetBuffersStatsReply{}
	request := &interfaces.GetBuffersStats{BufferIndex: 0}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(err, "update buffer stats failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return 0, 0, 0, fmt.Errorf("update buffer stats failed: req %+v reply %+v", request, response)
	}
	return response.AvailableBuffers, response.CachedBuffers, response.UsedBuffers, nil
}
