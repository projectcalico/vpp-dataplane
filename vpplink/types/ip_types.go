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
	"strings"

	"golang.org/x/sys/unix"

	vppip "github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/ip"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/ip_types"
)

type IPProto uint8

const (
	TCP     IPProto = IPProto(ip_types.IP_API_PROTO_TCP)
	UDP     IPProto = IPProto(ip_types.IP_API_PROTO_UDP)
	SCTP    IPProto = IPProto(ip_types.IP_API_PROTO_SCTP)
	ICMP    IPProto = IPProto(ip_types.IP_API_PROTO_ICMP)
	ICMP6   IPProto = IPProto(ip_types.IP_API_PROTO_ICMP6)
	INVALID IPProto = IPProto(ip_types.IP_API_PROTO_RESERVED)
)

type IPFlowHash uint8

const (
	FlowHashSrcIP     IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_SRC_IP)
	FlowHashDstIP     IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_DST_IP)
	FlowHashSrcPort   IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_SRC_PORT)
	FlowHashDstPort   IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_DST_PORT)
	FlowHashProto     IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_PROTO)
	FlowHashReverse   IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_REVERSE)
	FlowHashSymetric  IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_SYMETRIC)
	FlowHashFlowLabel IPFlowHash = IPFlowHash(vppip.IP_API_FLOW_HASH_FLOW_LABEL)
)

const (
	// Family type definitions
	FAMILY_ALL = unix.AF_UNSPEC
	FAMILY_V4  = unix.AF_INET
	FAMILY_V6  = unix.AF_INET6
)

type IfAddress struct {
	IPNet     net.IPNet
	SwIfIndex uint32
}

type IpPuntRedirect struct {
	RxSwIfIndex uint32
	IsIP6       bool
	Paths       []RoutePath
}

type VRF struct {
	Name  string
	VrfID uint32
	IsIP6 bool
}

func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return FAMILY_V4
	}
	if ip.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

func GetBoolIPFamily(isIP6 bool) ip_types.AddressFamily {
	if isIP6 {
		return ip_types.ADDRESS_IP6
	}
	return ip_types.ADDRESS_IP4
}

func IsIP4(ip net.IP) bool {
	return GetIPFamily(ip) == FAMILY_V4
}

func IsIP6(ip net.IP) bool {
	return GetIPFamily(ip) == FAMILY_V6
}

func (proto IPProto) String() string {
	switch proto {
	case UDP:
		return "UDP"
	case TCP:
		return "TCP"
	case SCTP:
		return "SCTP"
	case ICMP:
		return "ICMP"
	case ICMP6:
		return "ICMP6"
	default:
		return "???"
	}
}

func UnformatProto(proto string) (IPProto, error) {
	switch strings.ToUpper(proto) {
	case "UDP":
		return UDP, nil
	case "TCP":
		return TCP, nil
	case "SCTP":
		return SCTP, nil
	case "ICMP":
		return ICMP, nil
	case "ICMP6":
		return ICMP6, nil
	default:
		return IPProto(0), fmt.Errorf("unknown proto %s", proto)
	}
}

func ToVppIPProto(proto IPProto) ip_types.IPProto {
	return ip_types.IPProto(proto)
}

// Make sure you really call this with an IPv4 address...
func ToVppIP4Address(addr net.IP) ip_types.IP4Address {
	ip := [4]uint8{}
	copy(ip[:], addr.To4())
	return ip
}

func ToVppIP6Address(addr net.IP) ip_types.IP6Address {
	ip := [16]uint8{}
	copy(ip[:], addr)
	return ip
}

func ToVppAddress(addr net.IP) ip_types.Address {
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
	return FromVppIpAddressUnion(addr.Un, addr.Af == ip_types.ADDRESS_IP6)
}

func ToVppAddressWithPrefix(prefix *net.IPNet) ip_types.AddressWithPrefix {
	return ip_types.AddressWithPrefix(ToVppPrefix(prefix))
}

func ToVppPrefix(prefix *net.IPNet) ip_types.Prefix {
	len, _ := prefix.Mask.Size()
	r := ip_types.Prefix{
		Address: ToVppAddress(prefix.IP),
		Len:     uint8(len),
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
