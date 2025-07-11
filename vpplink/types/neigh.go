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
	"fmt"
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_neighbor"
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

type NeighborConfig struct {
	MaxNumber uint32
	MaxAge    uint32
	Recycle   bool
}

func (neighborConfig *NeighborConfig) String() string {
	return fmt.Sprintf(
		"max-number:%d max-age:%d recycle:%t",
		neighborConfig.MaxNumber,
		neighborConfig.MaxAge,
		neighborConfig.Recycle,
	)
}
