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

package vpplink

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/pbl"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) AddPblClient(client *types.PblClient) (id uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	portRanges := make([]pbl.PblPortRange, len(client.PortRanges))
	for _, r := range client.PortRanges {
		portRanges = append(portRanges, pbl.PblPortRange{
			Start: r.First,
			End: r.Last,
		})
	}

	response := &pbl.PblClientUpdateReply{}
	request := &pbl.PblClientUpdate{
		Client: pbl.PblClient{
			ID: client.ID,
			Addr: types.ToVppAddress(client.Addr),
			Paths: client.Path.ToFibPath(false),
			Flags: 0,
			PortRanges: portRanges,
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return 0, errors.Wrapf(err, "Pbl Client Update failed")
	} else if response.Retval != 0 {
		return 0, fmt.Errorf("Pbl Client Update failed with retval %d", response.Retval)
	}
	client.ID = response.ID
	return response.ID, nil
}

func (v *VppLink) DelPblClient(id uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &pbl.PblClientDelReply{}
	request := &pbl.PblClientDel{
		ID: id,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Pbl Client Delete failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Pbl Client Delete failed with retval %d", response.Retval)
	}
	return nil
}


