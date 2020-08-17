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

	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~303-g7aeaa83db/ip"
)

type RoutePath struct {
	Gw        net.IP
	SwIfIndex uint32
	Table     int
}

type Route struct {
	Dst   *net.IPNet
	Paths []RoutePath
	Table int
}

func (p *RoutePath) tableString() string {
	if p.Table == 0 {
		return ""
	} else {
		return fmt.Sprintf("[%d]", p.Table)
	}
}

func (p *RoutePath) swIfIndexString() string {
	if p.SwIfIndex == 0 {
		return ""
	} else {
		return fmt.Sprintf("[idx%d]", p.SwIfIndex)
	}
}

func (p *RoutePath) GetVppGwAddress() vppip.Address {
	return ToVppIpAddress(p.Gw)
}

func (p *RoutePath) String() string {
	return fmt.Sprintf("%s%s%s", p.tableString(), p.Gw.String(), p.swIfIndexString())
}

func (r *Route) GetVppDstAddress() vppip.Address {
	return ToVppIpAddress(r.Dst.IP)
}

func isV6toProto(addr net.IP) vppip.FibPathNhProto {
	if IsIP6(addr) {
		return vppip.FIB_API_PATH_NH_PROTO_IP6
	} else {
		return vppip.FIB_API_PATH_NH_PROTO_IP4
	}
}

func (r *Route) GetProto() vppip.FibPathNhProto {
	if r.Dst != nil {
		return isV6toProto(r.Dst.IP)
	}
	for _, path := range r.Paths {
		return isV6toProto(path.Gw)
	}
	return vppip.FIB_API_PATH_NH_PROTO_IP4
}

func (r *Route) pathsString() string {
	pathsStr := make([]string, 0, len(r.Paths))
	for _, path := range r.Paths {
		pathsStr = append(pathsStr, path.String())
	}
	return strings.Join(pathsStr, ", ")
}

func (r *Route) tableString() string {
	if r.Table == 0 {
		return ""
	} else {
		return fmt.Sprintf("[%d] ", r.Table)
	}
}

func (r *Route) dstString() string {
	if r.Dst == nil {
		return "*"
	} else {
		return r.Dst.String()
	}
}

func (r *Route) String() string {
	return fmt.Sprintf("%s%s -> %s", r.tableString(), r.dstString(), r.pathsString())
}

func (r *Route) IsLinkLocal() bool {
	if r.Dst == nil {
		return false
	}
	if !IsIP6(r.Dst.IP) {
		return false
	}
	return r.Dst.IP.IsLinkLocalUnicast()
}
