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

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/fib_types"
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

func (p *RoutePath) ToFibPath(isIP6 bool) fib_types.FibPath {
	// There is one case where we need an IPv4 route with an IPv6 path
	// (for broadcast)
	pathProto := IsV6toFibProto(isIP6)
	if p.Gw != nil {
		pathProto = IsV6toFibProto(p.Gw.To4() == nil)
	}
	fibPath := fib_types.FibPath{
		SwIfIndex:  uint32(p.SwIfIndex),
		TableID:    uint32(p.Table),
		RpfID:      0,
		Weight:     1,
		Preference: 0,
		Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
		Flags:      fib_types.FIB_API_PATH_FLAG_NONE,
		Proto:      pathProto,
	}
	if p.Gw != nil {
		fibPath.Nh.Address = ToVppAddress(p.Gw).Un
	}
	return fibPath
}

func (p *RoutePath) swIfIndexString() string {
	if p.SwIfIndex == 0 {
		return ""
	} else {
		return fmt.Sprintf("[idx%d]", p.SwIfIndex)
	}
}

func (p *RoutePath) String() string {
	return fmt.Sprintf("%s%s%s", p.tableString(), p.Gw.String(), p.swIfIndexString())
}

func IsV6toFibProto(isv6 bool) fib_types.FibPathNhProto {
	if isv6 {
		return fib_types.FIB_API_PATH_NH_PROTO_IP6
	}
	return fib_types.FIB_API_PATH_NH_PROTO_IP4
}

func (r *Route) IsIP6() bool {
	if r.Dst != nil {
		return IsIP6(r.Dst.IP)
	}
	for _, path := range r.Paths {
		return IsIP6(path.Gw)
	}
	return false
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

type IPFlowHash struct {
	Src       bool
	Dst       bool
	SrcPort   bool
	DstPort   bool
	Proto     bool
	Reverse   bool
	Symmetric bool
}
