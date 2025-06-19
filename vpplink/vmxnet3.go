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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/vmxnet3"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) CreateVmxnet3(intf *types.Vmxnet3Interface) (uint32, error) {
	pci, err := types.GetPciIDInt(intf.PciID)
	if err != nil {
		return 0, fmt.Errorf("error parsing PCI id: %w", err)
	}
	client := vmxnet3.NewServiceClient(v.GetConnection())

	request := &vmxnet3.Vmxnet3Create{
		PciAddr:   pci,
		RxqNum:    uint16(intf.NumRxQueues),
		RxqSize:   uint16(intf.RxQueueSize),
		TxqSize:   uint16(intf.TxQueueSize),
		TxqNum:    uint16(intf.NumTxQueues),
		EnableGso: intf.EnableGso,
	}
	response, err := client.Vmxnet3Create(v.GetContext(), request)
	if err != nil {
		return ^uint32(0), fmt.Errorf("failed to create Vmxnet3 interface: %w", err)
	}

	intf.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}
