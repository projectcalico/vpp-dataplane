// Copyright (C) 2025 Cisco Systems Inc.
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
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ttl_fixup"
)

// EnableTTLFixup enables the TTL fixup feature on a tap interface.
// This marks incoming packets with VNET_BUFFER_F_LOCALLY_ORIGINATED so that
// ip4/ip6-rewrite nodes skip TTL/hop-limit decrement, allowing VPP to act
// as a transparent forwarder for host traffic (DHCPv6, BGP, etc.) without
// counting as a router hop.
func (v *VppLink) EnableTTLFixup(swIfIndex uint32) error {
	return v.enableDisableTTLFixup(swIfIndex, true)
}

// DisableTTLFixup disables the TTL fixup input feature on an interface.
func (v *VppLink) DisableTTLFixup(swIfIndex uint32) error {
	return v.enableDisableTTLFixup(swIfIndex, false)
}

// EnableTTLFixupOutput enables the TTL fixup output feature on a pod interface.
// When enabled, the output node decrements TTL/hop-limit for packets that
// arrived from a source (tap) interface, restoring normal router-hop behaviour
// for host-to-pod traffic while keeping TTL preserved for host-to-uplink
// (transparent forwarding) traffic.
func (v *VppLink) EnableTTLFixupOutput(swIfIndex uint32) error {
	return v.enableDisableTTLFixupOutput(swIfIndex, true)
}

// DisableTTLFixupOutput disables the TTL fixup output feature on an interface.
func (v *VppLink) DisableTTLFixupOutput(swIfIndex uint32) error {
	return v.enableDisableTTLFixupOutput(swIfIndex, false)
}

func (v *VppLink) enableDisableTTLFixup(swIfIndex uint32, enable bool) error {
	client := ttl_fixup.NewServiceClient(v.GetConnection())

	request := &ttl_fixup.TTLFixupInputEnableDisable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Enable:    enable,
	}

	_, err := client.TTLFixupInputEnableDisable(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("TTLFixupInputEnableDisable failed: %w", err)
	}

	return nil
}

func (v *VppLink) enableDisableTTLFixupOutput(swIfIndex uint32, enable bool) error {
	client := ttl_fixup.NewServiceClient(v.GetConnection())

	request := &ttl_fixup.TTLFixupOutputEnableDisable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Enable:    enable,
	}

	_, err := client.TTLFixupOutputEnableDisable(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("TTLFixupOutputEnableDisable failed: %w", err)
	}

	return nil
}
