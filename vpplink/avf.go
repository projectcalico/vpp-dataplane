// Copyright (C) 2020 Cisco Systems Inc.
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
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/avf"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	AvfReplyTimeout = 15 * time.Second
)

func (v *VppLink) CreateAVF(intf *types.AVFInterface) (swIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	addr, err := types.GetPciIdInt(intf.PciId)
	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrapf(err, "CreateAVF error parsing PCI id")
	}
	response := &avf.AvfCreateReply{}
	request := &avf.AvfCreate{
		PciAddr: addr,
		RxqNum:  uint16(intf.NumRxQueues),
		RxqSize: uint16(intf.RxQueueSize),
		TxqSize: uint16(intf.TxQueueSize),
	}
	defer v.ch.SetReplyTimeout(DefaultReplyTimeout)
	v.ch.SetReplyTimeout(AvfReplyTimeout)
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrapf(err, "CreateAVF failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("CreateAVF failed: req %+v reply %+v", request, response)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteAVF(swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &avf.AvfDeleteReply{}
	request := &avf.AvfDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "DeleteAVF failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("DeleteAVF failed: req %+v reply %+v", request, response)
	}
	return nil
}
