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

package vpplink

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/fib_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_neighbor"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	AnyInterface = ^uint32(0)
)

func (v *VppLink) GetRoutes(tableID uint32, isIPv6 bool) (routes []types.Route, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &vppip.IPRouteDump{
		Table: vppip.IPTable{
			TableID: tableID,
			IsIP6:   isIPv6,
		},
	}
	response := &vppip.IPRouteDetails{}
	v.log.Debug("Listing VPP routes")
	stream := v.ch.SendMultiRequest(request)
	for {
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrap(err, "error listing VPP routes")
		}
		if stop {
			return routes, nil
		}
		vppRoute := response.Route
		routePaths := make([]types.RoutePath, 0, vppRoute.NPaths)
		for _, vppPath := range vppRoute.Paths {
			routePaths = append(routePaths, types.RoutePath{
				Gw: types.FromVppIpAddressUnion(
					vppPath.Nh.Address,
					vppRoute.Prefix.Address.Af == ip_types.ADDRESS_IP6,
				),
				Table:     int(vppPath.TableID),
				SwIfIndex: vppPath.SwIfIndex,
			})
		}

		route := types.Route{
			Dst:   types.FromVppPrefix(vppRoute.Prefix),
			Table: int(vppRoute.TableID),
			Paths: routePaths,
		}
		routes = append(routes, route)
	}
}

func (v *VppLink) AddNeighbor(neighbor *types.Neighbor) error {
	return v.addDelNeighbor(neighbor, true)
}

func (v *VppLink) DelNeighbor(neighbor *types.Neighbor) error {
	return v.addDelNeighbor(neighbor, false)
}

func isAddStr(isAdd bool) string {
	if isAdd {
		return "add"
	} else {
		return "delete"
	}
}

func (v *VppLink) addDelNeighbor(neighbor *types.Neighbor, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &ip_neighbor.IPNeighborAddDel{
		IsAdd: isAdd,
		Neighbor: ip_neighbor.IPNeighbor{
			SwIfIndex:  interface_types.InterfaceIndex(neighbor.SwIfIndex),
			Flags:      types.ToVppNeighborFlags(neighbor.Flags),
			MacAddress: types.ToVppMacAddress(&neighbor.HardwareAddr),
			IPAddress:  types.ToVppAddress(neighbor.IP),
		},
	}
	response := &ip_neighbor.IPNeighborAddDelReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to %s neighbor from VPP", isAddStr(isAdd))
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to %s neighbor from VPP (retval %d)", isAddStr(isAdd), response.Retval)
	}
	v.log.Debugf("%sed neighbor %+v", isAddStr(isAdd), neighbor)
	return nil
}

func (v *VppLink) RouteAdd(route *types.Route) error {
	return v.addDelIPRoute(route, true)
}

func (v *VppLink) RouteDel(route *types.Route) error {
	return v.addDelIPRoute(route, false)
}

func (v *VppLink) addDelIPRoute(route *types.Route, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	isIP6 := route.IsIP6()
	prefix := ip_types.Prefix{}
	if route.Dst != nil {
		prefix = types.ToVppPrefix(route.Dst)
	} else {
		prefix.Address = ip_types.Address{
			Af: types.ToVppAddressFamily(isIP6),
		}
	}

	paths := make([]fib_types.FibPath, 0, len(route.Paths))
	for _, routePath := range route.Paths {
		// There is one case where we need an IPv4 route with an IPv6 path (for broadcast)
		pathProto := types.IsV6toFibProto(isIP6)
		if routePath.Gw != nil {
			pathProto = types.IsV6toFibProto(routePath.Gw.To4() == nil)
		}
		path := fib_types.FibPath{
			SwIfIndex:  uint32(routePath.SwIfIndex),
			TableID:    uint32(routePath.Table),
			RpfID:      0,
			Weight:     1,
			Preference: 0,
			Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
			Flags:      fib_types.FIB_API_PATH_FLAG_NONE,
			Proto:      pathProto,
		}
		if routePath.Gw != nil {
			path.Nh.Address = types.ToVppAddress(routePath.Gw).Un
		}
		paths = append(paths, path)
	}

	vppRoute := vppip.IPRoute{
		TableID: uint32(route.Table),
		Prefix:  prefix,
		Paths:   paths,
	}

	request := &vppip.IPRouteAddDel{
		IsAdd: isAdd,
		Route: vppRoute,
	}

	response := &vppip.IPRouteAddDelReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to add/delete (%d) route from VPP", isAdd)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to add/delete (%d) route from VPP (retval %d)", isAdd, response.Retval)
	}
	v.log.Debugf("added/deleted (%d) route %+v", isAdd, route)
	return nil
}

func (v *VppLink) AddDefaultRouteViaTable(sourceTable, dstTable uint32, isIP6 bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	prefix := ip_types.Prefix{
		Address: ip_types.Address{
			Af: types.ToVppAddressFamily(isIP6),
		},
	}

	paths := []fib_types.FibPath{{
		SwIfIndex: AnyInterface,
		TableID:   dstTable,
		Proto:     types.IsV6toFibProto(isIP6),
	}}

	request := &vppip.IPRouteAddDel{
		IsAdd: true,
		Route: vppip.IPRoute{
			TableID: sourceTable,
			Prefix:  prefix,
			Paths:   paths,
		},
	}

	response := &vppip.IPRouteAddDelReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to add route to VPP")
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to add route to VPP (retval %d)", response.Retval)
	}
	return nil
}

func (v *VppLink) SetIPFlowHash(ipFlowHash *types.IPFlowHash, vrfID uint32, isIPv6 bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &vppip.SetIPFlowHash{
		VrfID:     vrfID,
		IsIPv6:    isIPv6,
		Src:       ipFlowHash.Src,
		Dst:       ipFlowHash.Dst,
		Sport:     ipFlowHash.SrcPort,
		Dport:     ipFlowHash.DstPort,
		Proto:     ipFlowHash.Proto,
		Reverse:   ipFlowHash.Reverse,
		Symmetric: ipFlowHash.Symmetric,
	}

	response := &vppip.SetIPFlowHashReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to update flow hash algo for vrf %d", vrfID)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to update flow hash algo for vrf %d (retval %d)", vrfID, response.Retval)
	}
	v.log.Debugf("updated flow hash algo for vrf %d", vrfID)
	return nil
}
