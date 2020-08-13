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
	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~215-g37bd1e445/ip"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~215-g37bd1e445/ip_neighbor"
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
				Gw:        types.FromVppIpAddressUnion(vppPath.Nh.Address, vppRoute.Prefix.Address.Af == vppip.ADDRESS_IP6),
				Table:     int(vppPath.TableID),
				SwIfIndex: vppPath.SwIfIndex,
			})
		}

		route := types.Route{
			Dst:   types.FromVppIpPrefix(vppRoute.Prefix),
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
			SwIfIndex:  ip_neighbor.InterfaceIndex(neighbor.SwIfIndex),
			Flags:      neighbor.GetVppNeighborFlags(),
			MacAddress: ip_neighbor.MacAddress(neighbor.GetVppMacAddress()),
			IPAddress:  neighbor.GetVppNeighborAddress(),
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

	prefix := vppip.Prefix{}
	if route.Dst != nil {
		prefixLen, _ := route.Dst.Mask.Size()
		prefix.Len = uint8(prefixLen)
		prefix.Address = route.GetVppDstAddress()
	}

	proto := route.GetProto()
	paths := make([]vppip.FibPath, 0, len(route.Paths))
	for _, routePath := range route.Paths {
		path := vppip.FibPath{
			SwIfIndex:  uint32(routePath.SwIfIndex),
			TableID:    uint32(routePath.Table),
			RpfID:      0,
			Weight:     1,
			Preference: 0,
			Type:       vppip.FIB_API_PATH_TYPE_NORMAL,
			Flags:      vppip.FIB_API_PATH_FLAG_NONE,
			Proto:      proto,
		}
		if routePath.Gw != nil {
			path.Nh.Address = routePath.GetVppGwAddress().Un
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

func (v *VppLink) SetIPFlowHash(vrfID uint32, isIPv6 bool, src bool, dst bool, sport bool, dport bool, proto bool, reverse bool, symmetric bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &vppip.SetIPFlowHash{
		VrfID:     vrfID,
		IsIPv6:    isIPv6,
		Src:       src,
		Dst:       dst,
		Sport:     sport,
		Dport:     dport,
		Proto:     proto,
		Reverse:   reverse,
		Symmetric: symmetric,
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
