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
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~187-gf9d9cd97b/af_packet"
)

func ToVppMacAddress(hardwareAddr *net.HardwareAddr) af_packet.MacAddress {
	hwAddr := [6]uint8{}
	copy(hwAddr[:], *hardwareAddr)
	return af_packet.MacAddress(hwAddr)
}

func (v *VppLink) CreateAfPacket(ifName string, hardwareAddr *net.HardwareAddr) (swIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &af_packet.AfPacketCreateReply{}
	request := &af_packet.AfPacketCreate{
		UseRandomHwAddr: true,
		HostIfName:      ifName,
	}
	if hardwareAddr != nil {
		request.UseRandomHwAddr = false
		request.HwAddr = ToVppMacAddress(hardwareAddr)
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrapf(err, "AfPacketCreate failed: req %+v reply %+v", request, response)
	}
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
	}
	return nil
}
