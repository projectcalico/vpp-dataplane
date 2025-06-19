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
	"strconv"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ethernet_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/pci_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/virtio"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func parsePciAddr(addr string) (*pci_types.PciAddress, error) {
	if len(addr) != 12 {
		return nil, fmt.Errorf("length must be 12")
	}
	domain, err := strconv.ParseUint(addr[0:4], 16, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}
	bus, err := strconv.ParseUint(addr[5:7], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid bus: %w", err)
	}
	slot, err := strconv.ParseUint(addr[8:10], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid slot: %w", err)
	}
	function, err := strconv.ParseUint(addr[11:], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid function: %w", err)
	}
	return &pci_types.PciAddress{
		Domain:   uint16(domain),
		Bus:      uint8(bus),
		Slot:     uint8(slot),
		Function: uint8(function),
	}, nil
}

func (v *VppLink) CreateVirtio(intf *types.VirtioInterface) (uint32, error) {
	addr, err := parsePciAddr(intf.PciID)
	if err != nil {
		return 0, fmt.Errorf("invalid PCI address %q: %w", intf.PciID, err)
	}

	client := virtio.NewServiceClient(v.GetConnection())

	request := &virtio.VirtioPciCreateV2{
		PciAddr:      *addr,
		UseRandomMac: false,
		VirtioFlags:  virtio.VIRTIO_API_FLAG_GSO | virtio.VIRTIO_API_FLAG_CSUM_OFFLOAD,
	}
	if intf.HardwareAddr != nil {
		request.MacAddress = ethernet_types.NewMacAddress(intf.HardwareAddr)
	}
	response, err := client.VirtioPciCreateV2(v.GetContext(), request)
	if err != nil {
		return 0, fmt.Errorf("failed to create virtio: %w", err)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteVirtio(swIfIndex uint32) error {
	client := virtio.NewServiceClient(v.GetConnection())

	_, err := client.VirtioPciDelete(v.GetContext(), &virtio.VirtioPciDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to delete virtio: %w", err)
	}

	return nil
}
