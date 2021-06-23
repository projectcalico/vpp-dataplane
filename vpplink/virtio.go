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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/pci_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/virtio"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func parsePciAddr(addr string) (*pci_types.PciAddress, error) {
	if len(addr) != 12 {
		return nil, fmt.Errorf("Invalid PCI address: %s", addr)
	}
	domain, err := strconv.ParseUint(addr[0:4], 16, 16)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse PCI address %s", addr)
	}
	bus, err := strconv.ParseUint(addr[5:7], 16, 8)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse PCI address %s", addr)
	}
	slot, err := strconv.ParseUint(addr[8:10], 16, 8)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse PCI address %s", addr)
	}
	function, err := strconv.ParseUint(addr[11:], 16, 8)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse PCI address %s", addr)
	}
	return &pci_types.PciAddress{
		Domain:   uint16(domain),
		Bus:      uint8(bus),
		Slot:     uint8(slot),
		Function: uint8(function),
	}, nil
}

func (v *VppLink) CreateVirtio(intf *types.VirtioInterface) (swIfIndex uint32, err error) {
	addr, err := parsePciAddr(intf.PciId)
	if err != nil {
		return ^uint32(0), errors.Wrap(err, "CreateVirtio failed")
	}
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &virtio.VirtioPciCreateV2Reply{}
	request := &virtio.VirtioPciCreateV2{
		PciAddr:      *addr,
		UseRandomMac: false,
		VirtioFlags:  virtio.VIRTIO_API_FLAG_GSO | virtio.VIRTIO_API_FLAG_CSUM_OFFLOAD,
	}
	if intf.HardwareAddr != nil {
		request.MacAddress = types.ToVppMacAddress(intf.HardwareAddr)
	}

	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(0), errors.Wrapf(err, "CreateVirtio failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return ^uint32(0), fmt.Errorf("CreateVirtio failed: req %+v reply %+v", request, response)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteVirtio(swIfIndex uint32) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &virtio.VirtioPciDeleteReply{}
	request := &virtio.VirtioPciDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "DeleteVirtio failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("DeleteVirtio failed: req %+v reply %+v", request, response)
	}
	return nil
}
