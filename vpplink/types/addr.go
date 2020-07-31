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

	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~215-g37bd1e445/ip"
)

type IPProto uint32

const (
	INVALID IPProto = 0
	UDP     IPProto = 1
	SCTP    IPProto = 2
	TCP     IPProto = 3
	ICMP    IPProto = 4
	ICMP6   IPProto = 5
)

type IfAddress struct {
	IPNet     net.IPNet
	SwIfIndex uint32
}

func ToVppIPProto(proto IPProto) uint8 {
	switch proto {
	case UDP:
		return uint8(vppip.IP_API_PROTO_UDP)
	case TCP:
		return uint8(vppip.IP_API_PROTO_TCP)
	case SCTP:
		return uint8(vppip.IP_API_PROTO_SCTP)
	case ICMP:
		return uint8(vppip.IP_API_PROTO_ICMP)
	case ICMP6:
		return uint8(vppip.IP_API_PROTO_ICMP6)
	default:
		return ^uint8(0)
	}
}

func formatProto(proto IPProto) string {
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
