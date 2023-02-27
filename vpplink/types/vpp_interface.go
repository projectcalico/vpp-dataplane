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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/af_packet"
	interfaces "github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/interface"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/interface_types"
)

type RxMode uint32

func (mode *RxMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "interrupt":
		*mode = InterruptRxMode
	case "polling":
		*mode = PollingRxMode
	case "adaptive":
		*mode = AdaptativeRxMode
	case "default":
		*mode = DefaultRxMode
	default:
		*mode = UnknownRxMode
	}
	return nil
}

const (
	InvalidInterface = interface_types.InterfaceIndex(^uint32(0))
)

const (
	UnknownRxMode    RxMode = 0
	PollingRxMode    RxMode = 1
	InterruptRxMode  RxMode = 2
	AdaptativeRxMode RxMode = 3
	DefaultRxMode    RxMode = 4

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
	Mtu       []uint32
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
	Flags af_packet.AfPacketFlags
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

func FormatRxMode(rxMode RxMode) string {
	switch rxMode {
	case InterruptRxMode:
		return "interrupt"
	case PollingRxMode:
		return "polling"
	case AdaptativeRxMode:
		return "adaptive"
	case DefaultRxMode:
		return "default"
	default:
		return "unknown"
	}
}

type InterfaceEventType int

const (
	InterfaceEventUnknown InterfaceEventType = iota
	InterfaceEventAdminUp
	InterfaceEventLinkUp
	InterfaceEventDeleted
)

type InterfaceEvent struct {
	SwIfIndex uint32
	Type      InterfaceEventType
}

func ToInterfaceEvent(e *interfaces.SwInterfaceEvent) InterfaceEvent {
	event := InterfaceEvent{
		SwIfIndex: uint32(e.SwIfIndex),
		Type:      InterfaceEventUnknown,
	}
	if e.Deleted {
		event.Type = InterfaceEventDeleted
	} else {
		switch {
		case e.Flags&interface_types.IF_STATUS_API_FLAG_LINK_UP != 0:
			event.Type = InterfaceEventLinkUp
		case e.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0:
			event.Type = InterfaceEventAdminUp
		}
	}
	return event
}
