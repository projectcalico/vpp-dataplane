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
	"context"
	"fmt"
	"time"

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/avf"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	AvfReplyTimeout = 15 * time.Second
)

func (v *VppLink) CreateAVF(intf *types.AVFInterface) (uint32, error) {
	client := avf.NewServiceClient(v.GetConnection())

	addr, err := types.GetPciIdInt(intf.PciId)
	if err != nil {
		return INVALID_SW_IF_INDEX, fmt.Errorf("create AVF error parsing PCI id: %w", err)
	}

	ctx, cancel := context.WithTimeout(v.GetContext(), AvfReplyTimeout)
	defer cancel()

	request := &avf.AvfCreate{
		PciAddr: addr,
		RxqNum:  uint16(intf.NumRxQueues),
		RxqSize: uint16(intf.RxQueueSize),
		TxqSize: uint16(intf.TxQueueSize),
	}
	response, err := client.AvfCreate(ctx, request)
	if err != nil {
		return INVALID_SW_IF_INDEX, fmt.Errorf("create AVF %+v failed: %w", request, err)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteAVF(swIfIndex uint32) error {
	client := avf.NewServiceClient(v.GetConnection())

	_, err := client.AvfDelete(v.GetContext(), &avf.AvfDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("delete AVF %v failed: %w", swIfIndex, err)
	}
	return nil
}
