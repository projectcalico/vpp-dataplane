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

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/af_packet"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/ethernet_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) CreateAfPacket(intf *types.AfPacketInterface) (swIfIndex uint32, err error) {
	client := af_packet.NewServiceClient(v.GetConnection())

	request := &af_packet.AfPacketCreateV3{
		Mode:             af_packet.AF_PACKET_API_MODE_ETHERNET,
		UseRandomHwAddr:  true,
		HostIfName:       intf.HostInterfaceName,
		RxFramesPerBlock: uint32(intf.RxQueueSize),
		TxFramesPerBlock: uint32(intf.TxQueueSize),
		RxFrameSize:      uint32(1024 * 8 * 8),
		TxFrameSize:      uint32(1024 * 8 * 8),
		NumRxQueues:      uint16(intf.NumRxQueues),
		NumTxQueues:      uint16(intf.NumTxQueues),
		Flags:            intf.Flags,
	}
	if intf.HardwareAddr != nil {
		request.UseRandomHwAddr = false
		request.HwAddr = ethernet_types.NewMacAddress(intf.HardwareAddr)
	}
	response, err := client.AfPacketCreateV3(v.GetContext(), request)
	if err != nil {
		return INVALID_SW_IF_INDEX, fmt.Errorf("failed to create AfPacket interface (%+v): %w", request, err)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteAfPacket(ifName string) error {
	client := af_packet.NewServiceClient(v.GetConnection())

	_, err := client.AfPacketDelete(v.GetContext(), &af_packet.AfPacketDelete{
		HostIfName: ifName,
	})
	if err != nil {
		return fmt.Errorf("failed to delete AfPacket interface (%s): %w", ifName, err)
	}
	return nil
}
