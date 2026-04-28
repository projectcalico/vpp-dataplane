// Copyright (C) 2026 Cisco Systems Inc.
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

	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/generated/bindings/ip_ttl_fixup"
)

// EnableTTLFixup configures TTL fixup for transparent host forwarding on
// the given (source, destination) interface pair. When enabled, packets
// arriving on srcSwIfIndex (tap) whose resolved adjacency points to
// dstSwIfIndex (uplink) will skip TTL/hop-limit decrement in ip4/ip6-rewrite,
// making VPP transparent for that forwarding path.
//
// Packets from tap destined for pod interfaces (different adjacency output)
// are NOT affected and decrement TTL normally.
func (v *VppLink) EnableTTLFixup(srcSwIfIndex, dstSwIfIndex uint32) error {
	return v.configureTTLFixup(srcSwIfIndex, dstSwIfIndex, true)
}

// DisableTTLFixup removes TTL fixup configuration for the given interface pair.
func (v *VppLink) DisableTTLFixup(srcSwIfIndex, dstSwIfIndex uint32) error {
	return v.configureTTLFixup(srcSwIfIndex, dstSwIfIndex, false)
}

func (v *VppLink) configureTTLFixup(srcSwIfIndex, dstSwIfIndex uint32, enable bool) error {
	client := ip_ttl_fixup.NewServiceClient(v.GetConnection())

	request := &ip_ttl_fixup.IPTTLFixupConfigure{
		SrcSwIfIndex: interface_types.InterfaceIndex(srcSwIfIndex),
		DstSwIfIndex: interface_types.InterfaceIndex(dstSwIfIndex),
		Enable:       enable,
	}

	_, err := client.IPTTLFixupConfigure(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("IPTTLFixupConfigure failed: %w", err)
	}

	return nil
}
