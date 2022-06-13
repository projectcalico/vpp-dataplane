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

package vppapi

import (
	"net"

    types2 "git.fd.io/govpp.git/api/v0"

    "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ethernet_types"
    "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
    "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_neighbor"
    "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
)

const (
	IPNeighborNone       types2.IPNeighborFlags = types2.IPNeighborFlags(ip_neighbor.IP_API_NEIGHBOR_FLAG_NONE)
	IPNeighborStatic     types2.IPNeighborFlags = types2.IPNeighborFlags(ip_neighbor.IP_API_NEIGHBOR_FLAG_STATIC)
	IPNeighborNoFibEntry types2.IPNeighborFlags = types2.IPNeighborFlags(ip_neighbor.IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY)
)

const (
	InvalidInterface = interface_types.InterfaceIndex(^uint32(0))
)

func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return types2.FAMILY_V4
	}
	if ip.To4() != nil {
		return types2.FAMILY_V4
	}
	return types2.FAMILY_V6
}

func FromVppNeighborFlags(flags ip_neighbor.IPNeighborFlags) types2.IPNeighborFlags {
	return types2.IPNeighborFlags(flags)
}

func IsIP6(ip net.IP) bool {
	return GetIPFamily(ip) == types2.FAMILY_V6
}

func toVppIPProto(proto types2.IPProto) ip_types.IPProto {
	switch proto {
	case types2.UDP:
		return ip_types.IP_API_PROTO_UDP
	case types2.TCP:
		return ip_types.IP_API_PROTO_TCP
	case types2.SCTP:
		return ip_types.IP_API_PROTO_SCTP
	case types2.ICMP:
		return ip_types.IP_API_PROTO_ICMP
	case types2.ICMP6:
		return ip_types.IP_API_PROTO_ICMP6
	}
	return ip_types.IP_API_PROTO_RESERVED
}

func toVppIP4Address(addr net.IP) ip_types.IP4Address {
	ip := [4]uint8{}
	copy(ip[:], addr.To4())
	return ip
}

func toVppIP6Address(addr net.IP) ip_types.IP6Address {
	ip := [16]uint8{}
	copy(ip[:], addr)
	return ip
}

func toVppAddress(addr net.IP) ip_types.Address {
	a := ip_types.Address{}
	if addr.To4() == nil {
		a.Af = ip_types.ADDRESS_IP6
		ip := [16]uint8{}
		copy(ip[:], addr)
		a.Un = ip_types.AddressUnionIP6(ip)
	} else {
		a.Af = ip_types.ADDRESS_IP4
		ip := [4]uint8{}
		copy(ip[:], addr.To4())
		a.Un = ip_types.AddressUnionIP4(ip)
	}
	return a
}

func FromVppIpAddressUnion(Un ip_types.AddressUnion, isv6 bool) net.IP {
	if isv6 {
		a := Un.GetIP6()
		return net.IP(a[:])
	} else {
		a := Un.GetIP4()
		return net.IP(a[:])
	}
}

func FromVppAddress(addr ip_types.Address) net.IP {
	return FromVppIpAddressUnion(
		ip_types.AddressUnion(addr.Un),
		addr.Af == ip_types.ADDRESS_IP6,
	)
}

func ToVppAddressWithPrefix(prefix *net.IPNet) ip_types.AddressWithPrefix {
	return ip_types.AddressWithPrefix(toVppPrefix(prefix))
}

func toVppPrefix(prefix *net.IPNet) ip_types.Prefix {
	l, _ := prefix.Mask.Size()
	r := ip_types.Prefix{
		Address: toVppAddress(prefix.IP),
		Len:     uint8(l),
	}
	return r
}

func toVppIp4WithPrefix(prefix *net.IPNet) ip_types.IP4AddressWithPrefix {
	return ip_types.IP4AddressWithPrefix(toVppIP4Prefix(prefix))
}

func toVppIP4Prefix(prefix *net.IPNet) ip_types.IP4Prefix {
	l, _ := prefix.Mask.Size()
	r := ip_types.IP4Prefix{
		Address: toVppIP4Address(prefix.IP),
		Len:     uint8(l),
	}
	return r
}

func FromVppAddressWithPrefix(prefix ip_types.AddressWithPrefix) *net.IPNet {
	return FromVppPrefix(ip_types.Prefix(prefix))
}

func FromVppPrefix(prefix ip_types.Prefix) *net.IPNet {
	addressSize := 32
	if prefix.Address.Af == ip_types.ADDRESS_IP6 {
		addressSize = 128
	}
	return &net.IPNet{
		IP:   FromVppAddress(prefix.Address),
		Mask: net.CIDRMask(int(prefix.Len), addressSize),
	}
}

func ToVppAddressFamily(isv6 bool) ip_types.AddressFamily {
	if isv6 {
		return ip_types.ADDRESS_IP6
	}
	return ip_types.ADDRESS_IP4
}

func ToVppPrefix(prefix *net.IPNet) ip_types.Prefix {
	l, _ := prefix.Mask.Size()
	r := ip_types.Prefix{
		Address: ip_types.AddressFromIP(prefix.IP),
		Len:     uint8(l),
	}
	return r
}

func ToVppMacAddress(hardwareAddr *net.HardwareAddr) ethernet_types.MacAddress {
	hwAddr := [6]uint8{}
	copy(hwAddr[:], *hardwareAddr)
	return ethernet_types.MacAddress(hwAddr)
}

func FromVppMacAddress(vppHwAddr ethernet_types.MacAddress) net.HardwareAddr {
	return net.HardwareAddr(vppHwAddr[:])
}
