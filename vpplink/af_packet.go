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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/af_packet"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) CreateAfPacket(intf *types.AfPacketInterface) (swIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &af_packet.AfPacketCreateV2Reply{}
	request := &af_packet.AfPacketCreateV2{
		UseRandomHwAddr:  true,
		HostIfName:       intf.HostInterfaceName,
		RxFramesPerBlock: uint32(intf.RxQueueSize),
		TxFramesPerBlock: uint32(intf.TxQueueSize),
	}
	if intf.HardwareAddr != nil {
		request.UseRandomHwAddr = false
		request.HwAddr = types.ToVppMacAddress(intf.HardwareAddr)
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrapf(err, "AfPacketCreate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("AfPacketCreate failed: req %+v reply %+v", request, response)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteAfPacket(ifName string) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &af_packet.AfPacketDeleteReply{}
	request := &af_packet.AfPacketDelete{
		HostIfName: ifName,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "AfPacketDelete failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("AfPacketDelete failed: req %+v reply %+v", request, response)
	}
	return nil
}
