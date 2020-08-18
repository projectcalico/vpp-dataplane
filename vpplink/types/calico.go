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

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~214-g61309b2f8/calico"
)

type CalicoEndpoint struct {
	IP   net.IP
	Port uint16
}

func (e *CalicoEndpoint) String() string {
	return fmt.Sprintf("%s;%d",
		e.IP.String(),
		e.Port,
	)
}

type CalicoEndpointTuple struct {
	SrcEndpoint CalicoEndpoint
	DstEndpoint CalicoEndpoint
}

func (t *CalicoEndpointTuple) String() string {
	return fmt.Sprintf("%s -> %s",
		t.SrcEndpoint.String(),
		t.DstEndpoint.String(),
	)
}

type CalicoTranslateEntry struct {
	Endpoint CalicoEndpoint
	Backends []CalicoEndpointTuple
	Proto    IPProto
	IsRealIP bool
	ID       uint32
}

func (n *CalicoTranslateEntry) String() string {
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

func (n *CalicoTranslateEntry) Equal(o *CalicoTranslateEntry) bool {
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

func ToCalicoProto(proto IPProto) calico.IPProto {
	switch proto {
	case UDP:
		return calico.IP_API_PROTO_UDP
	case TCP:
		return calico.IP_API_PROTO_TCP
	case SCTP:
		return calico.IP_API_PROTO_SCTP
	case ICMP:
		return calico.IP_API_PROTO_ICMP
	case ICMP6:
		return calico.IP_API_PROTO_ICMP6
	default:
		return calico.IP_API_PROTO_RESERVED
	}
}

func ToCalicoEndpoint(ep CalicoEndpoint) calico.CalicoEndpoint {
	a := calico.CalicoEndpoint{
		Port: ep.Port,
	}
	if ep.IP.To4() == nil {
		a.Addr.Af = calico.ADDRESS_IP6
		ip := [16]uint8{}
		copy(ip[:], ep.IP)
		a.Addr.Un = calico.AddressUnionIP6(ip)
	} else {
		a.Addr.Af = calico.ADDRESS_IP4
		ip := [4]uint8{}
		copy(ip[:], ep.IP.To4())
		a.Addr.Un = calico.AddressUnionIP4(ip)
	}
	return a
}

func ToVppCalicoAddress(addr net.IP) calico.Address {
	a := calico.Address{}
	if addr.To4() == nil {
		a.Af = calico.ADDRESS_IP6
		ip := [16]uint8{}
		copy(ip[:], addr)
		a.Un = calico.AddressUnionIP6(ip)
	} else {
		a.Af = calico.ADDRESS_IP4
		ip := [4]uint8{}
		copy(ip[:], addr.To4())
		a.Un = calico.AddressUnionIP4(ip)
	}
	return a
}

func ToVppCalicoPrefix(prefix *net.IPNet) calico.Prefix {
	len, _ := prefix.Mask.Size()
	r := calico.Prefix{
		Address: ToVppCalicoAddress(prefix.IP),
		Len:     uint8(len),
	}
	return r
}

// Make sure you really call this with an IPv4 address...
func ToVppCalicoIp4Address(addr net.IP) calico.IP4Address {
	ip := [4]uint8{}
	copy(ip[:], addr.To4())
	return ip
}

func ToVppCalicoIp6Address(addr net.IP) calico.IP6Address {
	ip := [16]uint8{}
	copy(ip[:], addr)
	return ip
}
