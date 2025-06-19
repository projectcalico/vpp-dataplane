// Copyright (C) 2022 Cisco Systems Inc.
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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/urpf"
)

func (v *VppLink) SetCustomURPF(swifindex uint32, tableID uint32) error {
	client := urpf.NewServiceClient(v.GetConnection())

	_, err := client.UrpfUpdateV2(v.GetContext(), &urpf.UrpfUpdateV2{
		Mode:      urpf.URPF_API_MODE_LOOSE,
		SwIfIndex: interface_types.InterfaceIndex(swifindex),
		Af:        ip_types.ADDRESS_IP4,
		IsInput:   true,
		TableID:   tableID,
	})
	if err != nil {
		return fmt.Errorf("failed to set URPF mode to loose: %w", err)
	}
	return nil
}

func (v *VppLink) UnsetURPF(swifindex uint32) error {
	client := urpf.NewServiceClient(v.GetConnection())

	_, err := client.UrpfUpdateV2(v.GetContext(), &urpf.UrpfUpdateV2{
		Mode:      urpf.URPF_API_MODE_OFF,
		SwIfIndex: interface_types.InterfaceIndex(swifindex),
		Af:        ip_types.ADDRESS_IP4,
		IsInput:   true,
	})
	if err != nil {
		return fmt.Errorf("failed to set URPF mode to off: %w", err)
	}

	return nil
}
