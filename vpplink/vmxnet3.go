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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/vmxnet3"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) CreateVmxnet3(intf *types.Vmxnet3Interface) (swIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &vmxnet3.Vmxnet3CreateReply{}
	pci, err := types.GetPciIdInt(intf.PciId)
	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrapf(err, "CreateVmxnet3 error parsing PCI id")
	}
	request := &vmxnet3.Vmxnet3Create{
		PciAddr:   pci,
		RxqNum:    uint16(intf.NumRxQueues),
		RxqSize:   uint16(intf.RxQueueSize),
		TxqSize:   uint16(intf.TxQueueSize),
		TxqNum:    uint16(intf.NumTxQueues),
		EnableGso: intf.EnableGso,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(0), errors.Wrapf(err, "CreateVmxnet3 failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return ^uint32(0), fmt.Errorf("CreateVmxnet3 failed: req %+v reply %+v", request, response)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}
