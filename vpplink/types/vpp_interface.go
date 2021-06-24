// Copyright (C) 2019 Cisco Systems Inc.
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
	"net"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
)

type RxMode uint32

const (
	InvalidInterface = interface_types.InterfaceIndex(^uint32(0))
)

const (
	UnknownRxMode RxMode = 0
	Polling       RxMode = 1
	Interrupt     RxMode = 2
	Adaptative    RxMode = 3
	DefaultRxMode RxMode = 4

	AllQueues = ^uint32(0)
)

type GenericVppInterface struct {
	Name              string /* Desired name in VPP */
	HostInterfaceName string /* Name of the host interface */
	HardwareAddr      *net.HardwareAddr
	NumRxQueues       int
	NumTxQueues       int
	TxQueueSize       int
	RxQueueSize       int
	/* return value on create */
	SwIfIndex uint32
}

type VppInterfaceDetails struct {
	SwIfIndex uint32
	IsUp      bool
	Name      string
	Tag       string
	Type      string
}

type TapFlags uint32

const (
	TapFlagNone        TapFlags = 0
	TapFlagGSO         TapFlags = 1
	TapFlagCsumOffload TapFlags = 2
	TapFlagPersist     TapFlags = 4
	TapFlagAttach      TapFlags = 8
	TapFlagTun         TapFlags = 16
	TapGROCoalesce     TapFlags = 32
)

type VppXDPInterface struct {
	GenericVppInterface
}

type AfPacketInterface struct {
	GenericVppInterface
}

type VirtioInterface struct {
	GenericVppInterface
	PciId string
}

type AVFInterface struct {
	GenericVppInterface
	PciId string
}

type Vmxnet3Interface struct {
	GenericVppInterface
	PciId     string
	EnableGso bool
}

type RDMAInterface struct {
	GenericVppInterface
}

type TapV2 struct {
	GenericVppInterface
	HostNamespace  string
	Tag            string
	HostMacAddress net.HardwareAddr
	Flags          TapFlags
	HostMtu        int
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

func UnformatRxMode(str string) RxMode {
	switch str {
	case "interrupt":
		return Interrupt
	case "polling":
		return Polling
	case "adaptive":
		return Adaptative
	default:
		return UnknownRxMode
	}
}

func FormatRxMode(rxMode RxMode) string {
	switch rxMode {
	case Interrupt:
		return "interrupt"
	case Polling:
		return "polling"
	case Adaptative:
		return "adaptive"
	default:
		return "default"
	}
}
