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
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/vmxnet3"
)

type Vmxnet3Info struct {
	RxqNum    int
	RxqSize   int
	TxqSize   int
	TxqNum    int
	EnableGso bool
}

func GetPciIdInt(PciIdStr string) (id uint32, err error) {
	/* 0000:d8:00.1 */
	re := regexp.MustCompile("([0-9a-f]{4}):([0-9a-f]{2}):([0-9a-f]{2}).([0-9a-f])")
	match := re.FindStringSubmatch(PciIdStr)
	if len(match) != 5 {
		return 0, errors.Errorf("Couldnt parse kernel pciID %s : %v", PciIdStr, match)
	}
	domain, err := strconv.ParseInt(match[1], 16, 32)
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt parse PCI domain: %v", err)
	}
	bus, err := strconv.ParseInt(match[2], 16, 16)
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt parse PCI bus: %v", err)
	}
	slot, err := strconv.ParseInt(match[3], 16, 16)
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt parse PCI slot: %v", err)
	}
	function, err := strconv.ParseInt(match[4], 16, 16)
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt parse PCI function: %v", err)
	}
	/* 16 bits domain / 8 bits bus / 5bits slot / 3bits function*/
	/* But this is VPP so endianess is all over the place */
	b := []byte{
		byte((domain >> 2) & 0xff),
		byte(domain & 0xff),
		byte(bus & 0xff),
		byte(((function & 7) << 5) | (slot & 31)),
	}
	id = binary.LittleEndian.Uint32(b)
	return id, nil
}

func (v *VppLink) CreateVmxnet3(addr string, vmxnet3Info Vmxnet3Info) (swIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &vmxnet3.Vmxnet3CreateReply{}
	pci, err := GetPciIdInt(addr)
	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrapf(err, "CreateVmxnet3 error parsing PCI id")
	}
	request := &vmxnet3.Vmxnet3Create{
		PciAddr:   pci,
		RxqNum:    uint16(vmxnet3Info.RxqNum),
		RxqSize:   uint16(vmxnet3Info.RxqSize),
		TxqSize:   uint16(vmxnet3Info.TxqSize),
		TxqNum:    uint16(vmxnet3Info.TxqNum),
		EnableGso: vmxnet3Info.EnableGso,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(0), errors.Wrapf(err, "CreateVmxnet3 failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return ^uint32(0), fmt.Errorf("CreateVmxnet3 failed: req %+v reply %+v", request, response)
	}
	return uint32(response.SwIfIndex), nil
}
