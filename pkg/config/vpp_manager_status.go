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

package config

import (
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
)

type vppManagerStatus string

const (
	Ready    vppManagerStatus = "ready"
	Starting vppManagerStatus = "starting"
)

type UplinkStatus struct {
	SwIfIndex           uint32
	TapSwIfIndex        uint32
	LinkIndex           int
	Name                string
	IsMain              bool
	Mtu                 int
	PhysicalNetworkName string

	// FakeNextHopIP4 is the computed next hop for v4 routes added
	// in linux to (ServiceCIDR, podCIDR, etc...) towards this interface
	FakeNextHopIP4 net.IP
	// FakeNextHopIP6 is the computed next hop for v6 routes added
	// in linux to (ServiceCIDR, podCIDR, etc...) towards this interface
	FakeNextHopIP6 net.IP

	UplinkAddresses []*net.IPNet
}

func (uplinkStatus *UplinkStatus) GetAddress(ipFamily vpplink.IPFamily) *net.IPNet {
	for _, addr := range uplinkStatus.UplinkAddresses {
		if vpplink.IPFamilyFromIPNet(addr) == ipFamily {
			return addr
		}
	}
	return nil
}

type PhysicalNetwork struct {
	VrfID    uint32
	PodVrfID uint32
}

type VppManagerInfo struct {
	Status         vppManagerStatus
	UplinkStatuses map[string]UplinkStatus
	PhysicalNets   map[string]PhysicalNetwork
}

func (i *VppManagerInfo) GetMainSwIfIndex() uint32 {
	for _, u := range i.UplinkStatuses {
		if u.IsMain {
			return u.SwIfIndex
		}
	}
	return vpplink.InvalidSwIfIndex
}
