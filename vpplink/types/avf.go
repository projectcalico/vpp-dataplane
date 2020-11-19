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

package types

import (
	"encoding/binary"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
)

type AVFInterface struct {
	NumRxQueues int
	TxQueueSize int
	RxQueueSize int
	PciId       string
}

func (ai *AVFInterface) GetPciId() (id uint32, err error) {
	/* 0000:d8:00.1 */
	re := regexp.MustCompile("([0-9a-f]{4}):([0-9a-f]{2}):([0-9a-f]{2}).([0-9a-f])")
	match := re.FindStringSubmatch(ai.PciId)
	if len(match) != 5 {
		return 0, errors.Errorf("Couldnt parse kernel pciID %s : %v", ai.PciId, match)
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
