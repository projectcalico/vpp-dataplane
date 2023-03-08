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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/af_xdp"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) CreateAfXDP(intf *types.VppXDPInterface) error {
	client := af_xdp.NewServiceClient(v.GetConnection())

	request := &af_xdp.AfXdpCreate{
		HostIf:  intf.HostInterfaceName,
		Name:    intf.Name,
		RxqNum:  uint16(DefaultIntTo(intf.NumRxQueues, 1)),
		RxqSize: uint16(DefaultIntTo(intf.RxQueueSize, 1024)),
		TxqSize: uint16(DefaultIntTo(intf.TxQueueSize, 1024)),
		Mode:    af_xdp.AF_XDP_API_MODE_AUTO,
	}
	response, err := client.AfXdpCreate(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("failed to create AfXDP (%+v): %w", request, err)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return nil
}

func (v *VppLink) DeleteAfXDP(intf *types.VppXDPInterface) error {
	client := af_xdp.NewServiceClient(v.GetConnection())

	_, err := client.AfXdpDelete(v.GetContext(), &af_xdp.AfXdpDelete{
		SwIfIndex: interface_types.InterfaceIndex(intf.SwIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to delete AfXDP (%v): %w", intf.SwIfIndex, err)
	}
	return nil
}
