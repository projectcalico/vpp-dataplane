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
	"net"

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-gab9444728/ethernet_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-gab9444728/ip_neighbor"
)

type IPNeighborFlags uint32

const (
	IPNeighborNone       IPNeighborFlags = IPNeighborFlags(ip_neighbor.IP_API_NEIGHBOR_FLAG_NONE)
	IPNeighborStatic     IPNeighborFlags = IPNeighborFlags(ip_neighbor.IP_API_NEIGHBOR_FLAG_STATIC)
	IPNeighborNoFibEntry IPNeighborFlags = IPNeighborFlags(ip_neighbor.IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY)
)

type Neighbor struct {
	SwIfIndex    uint32
	IP           net.IP
	HardwareAddr net.HardwareAddr
	Flags        IPNeighborFlags
}

func ToVppNeighborFlags(flags IPNeighborFlags) ip_neighbor.IPNeighborFlags {
	return ip_neighbor.IPNeighborFlags(flags)
}

func FromVppNeighborFlags(flags ip_neighbor.IPNeighborFlags) IPNeighborFlags {
	return IPNeighborFlags(flags)
}

func FromVppMacAddress(vppHwAddr ethernet_types.MacAddress) net.HardwareAddr {
	return net.HardwareAddr(vppHwAddr[:])
}

func ToVppMacAddress(hardwareAddr *net.HardwareAddr) ethernet_types.MacAddress {
	hwAddr := [6]uint8{}
	copy(hwAddr[:], *hardwareAddr)
	return ethernet_types.MacAddress(hwAddr)
}
