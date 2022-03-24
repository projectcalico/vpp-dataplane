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

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/cnat"
)

const (
	CnatNoNat = uint8(cnat.CNAT_EPT_NO_NAT)
)

type CnatLbType uint8

const (
	DefaultLB = CnatLbType(cnat.CNAT_LB_TYPE_DEFAULT)
	MaglevLB  = CnatLbType(cnat.CNAT_LB_TYPE_MAGLEV)
)

type CnatEndpoint struct {
	IP   net.IP
	Port uint16
}

func (e *CnatEndpoint) String() string {
	if e.IP.IsUnspecified() && e.Port == 0 {
		return "()"
	} else if e.IP.IsUnspecified() && e.Port != 0 {
		return fmt.Sprintf("();%d", e.Port)
	} else if e.Port == 0 {
		return fmt.Sprintf("%s", e.IP.String())
	} else {
		return fmt.Sprintf("%s;%d", e.IP.String(), e.Port)
	}
}

type CnatEndpointTuple struct {
	SrcEndpoint CnatEndpoint
	DstEndpoint CnatEndpoint
	Flags       uint8
}

func (t *CnatEndpointTuple) String() string {
	return fmt.Sprintf("[%s->%s]",
		t.SrcEndpoint.String(),
		t.DstEndpoint.String(),
	)
}

func (e *CnatTranslateEntry) Key() string {
	return fmt.Sprintf("%s#%s#%d", e.Proto.String(), e.Endpoint.IP, e.Endpoint.Port)
}

type CnatTranslateEntry struct {
	Endpoint CnatEndpoint
	Backends []CnatEndpointTuple
	Proto    IPProto
	IsRealIP bool
	LbType   CnatLbType
}

func (n *CnatTranslateEntry) String() string {
	strLst := make([]string, 0, len(n.Backends))
	for _, e := range n.Backends {
		strLst = append(strLst, e.String())
	}
	return fmt.Sprintf("[%s real=%t lbtyp=%d vip=%s rw=%s]",
		n.Proto.String(),
		n.IsRealIP,
		n.LbType,
		n.Endpoint.String(),
		strings.Join(strLst, ", "),
	)
}

type ObjEqualityState int

const (
	AreEqualObj       ObjEqualityState = iota /* objects are equal */
	CanUpdateObj                              /* objects differ, but you can call update */
	ShouldRecreateObj                         /* object differ, you need to delete the old & add back the new */
)

func (n *CnatTranslateEntry) Equal(oldService *CnatTranslateEntry) ObjEqualityState {
	if n == nil || oldService == nil {
		return ShouldRecreateObj
	}
	if n.Proto != oldService.Proto {
		return ShouldRecreateObj
	}
	if n.IsRealIP != oldService.IsRealIP {
		return ShouldRecreateObj
	}
	if n.Endpoint.Port != oldService.Endpoint.Port {
		return ShouldRecreateObj
	}
	if !n.Endpoint.IP.Equal(oldService.Endpoint.IP) {
		return ShouldRecreateObj
	}
	if len(n.Backends) == 0 && len(oldService.Backends) > 0 {
		/* We do not keep cnat entries with no backends in VPP */
		return ShouldRecreateObj
	}
	if n.LbType != oldService.LbType {
		return CanUpdateObj
	}
	if len(n.Backends) != len(oldService.Backends) {
		return CanUpdateObj
	}
	nMap := make(map[string]bool)
	for _, i := range n.Backends {
		nMap[i.String()] = true
	}
	for _, i := range oldService.Backends {
		if _, ok := nMap[i.String()]; !ok {
			return CanUpdateObj
		}
	}
	return AreEqualObj
}

func ToCnatEndpoint(ep CnatEndpoint) cnat.CnatEndpoint {
	return cnat.CnatEndpoint{
		Port:      ep.Port,
		Addr:      ToVppAddress(ep.IP),
		SwIfIndex: InvalidInterface,
	}

}
