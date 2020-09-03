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

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-g3a42319eb/cnat"
)

type CnatEndpoint struct {
	IP   net.IP
	Port uint16
}

func (e *CnatEndpoint) String() string {
	return fmt.Sprintf("%s;%d",
		e.IP.String(),
		e.Port,
	)
}

type CnatEndpointTuple struct {
	SrcEndpoint CnatEndpoint
	DstEndpoint CnatEndpoint
}

func (t *CnatEndpointTuple) String() string {
	return fmt.Sprintf("%s -> %s",
		t.SrcEndpoint.String(),
		t.DstEndpoint.String(),
	)
}

type CnatTranslateEntry struct {
	Endpoint CnatEndpoint
	Backends []CnatEndpointTuple
	Proto    IPProto
	IsRealIP bool
	ID       uint32
}

func (n *CnatTranslateEntry) String() string {
	strLst := make([]string, 0, len(n.Backends))
	for _, e := range n.Backends {
		strLst = append(strLst, e.String())
	}
	return fmt.Sprintf("%s %s => [%s]",
		formatProto(n.Proto),
		n.Endpoint.String(),
		strings.Join(strLst, ", "),
	)
}

func (n *CnatTranslateEntry) Equal(o *CnatTranslateEntry) bool {
	if n == nil || o == nil {
		return false
	}
	if n.Proto != o.Proto {
		return false
	}
	if n.Endpoint.Port != o.Endpoint.Port {
		return false
	}
	if !n.Endpoint.IP.Equal(o.Endpoint.IP) {
		return false
	}
	if len(n.Backends) != len(o.Backends) {
		return false
	}
	nMap := make(map[string]bool)
	for _, i := range n.Backends {
		nMap[i.String()] = true
	}
	for _, i := range o.Backends {
		if _, ok := nMap[i.String()]; !ok {
			return false
		}
	}
	return true
}

func ToCnatProto(proto IPProto) cnat.IPProto {
	switch proto {
	case UDP:
		return cnat.IP_API_PROTO_UDP
	case TCP:
		return cnat.IP_API_PROTO_TCP
	case SCTP:
		return cnat.IP_API_PROTO_SCTP
	case ICMP:
		return cnat.IP_API_PROTO_ICMP
	case ICMP6:
		return cnat.IP_API_PROTO_ICMP6
	default:
		return cnat.IP_API_PROTO_RESERVED
	}
}

func ToCnatEndpoint(ep CnatEndpoint) cnat.CnatEndpoint {
	a := cnat.CnatEndpoint{
		Port: ep.Port,
	}
	if ep.IP.To4() == nil {
		a.Addr.Af = cnat.ADDRESS_IP6
		ip := [16]uint8{}
		copy(ip[:], ep.IP)
		a.Addr.Un = cnat.AddressUnionIP6(ip)
	} else {
		a.Addr.Af = cnat.ADDRESS_IP4
		ip := [4]uint8{}
		copy(ip[:], ep.IP.To4())
		a.Addr.Un = cnat.AddressUnionIP4(ip)
	}
	return a
}

func ToVppCnatAddress(addr net.IP) cnat.Address {
	a := cnat.Address{}
	if addr.To4() == nil {
		a.Af = cnat.ADDRESS_IP6
		ip := [16]uint8{}
		copy(ip[:], addr)
		a.Un = cnat.AddressUnionIP6(ip)
	} else {
		a.Af = cnat.ADDRESS_IP4
		ip := [4]uint8{}
		copy(ip[:], addr.To4())
		a.Un = cnat.AddressUnionIP4(ip)
	}
	return a
}

func ToVppCnatPrefix(prefix *net.IPNet) cnat.Prefix {
	len, _ := prefix.Mask.Size()
	r := cnat.Prefix{
		Address: ToVppCnatAddress(prefix.IP),
		Len:     uint8(len),
	}
	return r
}

// Make sure you really call this with an IPv4 address...
func ToVppCnatIp4Address(addr net.IP) cnat.IP4Address {
	ip := [4]uint8{}
	copy(ip[:], addr.To4())
	return ip
}

func ToVppCnatIp6Address(addr net.IP) cnat.IP6Address {
	ip := [16]uint8{}
	copy(ip[:], addr)
	return ip
}
