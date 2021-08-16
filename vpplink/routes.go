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
	"net"

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
		route := types.Route{
			Dst:   types.FromVppPrefix(response.Route.Prefix),
			Table: response.Route.TableID,
			Paths: types.FromFibPathList(response.Route.Paths),
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

func (v *VppLink) RoutesAdd(Dsts []*net.IPNet, routepath *types.RoutePath) error {
	/* add the same route for multiple dsts */
	for _, dst := range Dsts {
		route := types.Route{
			Dst:   dst,
			Paths: []types.RoutePath{*routepath},
		}
		err := v.addDelIPRoute(&route, true)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}
	}
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
		paths = append(paths, routePath.ToFibPath(isIP6))
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

func (v *VppLink) addDelDefaultRouteViaTable(sourceTable, dstTable uint32, isIP6 bool, isAdd bool) error {
	route := &types.Route{
		Paths: []types.RoutePath{{
			Table:     dstTable,
			SwIfIndex: types.InvalidID,
		}},
		Dst:   &net.IPNet{IP: net.IPv4zero},
		Table: sourceTable,
	}
	if isIP6 {
		route.Dst.IP = net.IPv6zero
	}
	return v.addDelIPRoute(route, isAdd /*isAdd*/)
}

func (v *VppLink) AddDefaultRouteViaTable(sourceTable, dstTable uint32, isIP6 bool) error {
	return v.addDelDefaultRouteViaTable(sourceTable, dstTable, isIP6, true /*isAdd*/)
}

func (v *VppLink) DelDefaultRouteViaTable(sourceTable, dstTable uint32, isIP6 bool) error {
	return v.addDelDefaultRouteViaTable(sourceTable, dstTable, isIP6, false /*isAdd*/)
}

func (v *VppLink) AddDefault46RouteViaTable(sourceTable, dstTable uint32) (err error) {
	err = v.AddDefaultRouteViaTable(sourceTable, dstTable, false /*isip6*/)
	if err != nil {
		return err
	}
	err = v.AddDefaultRouteViaTable(sourceTable, dstTable, true /*isip6*/)
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) DelDefault46RouteViaTable(sourceTable, dstTable uint32) (err error) {
	err1 := v.DelDefaultRouteViaTable(sourceTable, dstTable, false /*isip6*/)
	err2 := v.DelDefaultRouteViaTable(sourceTable, dstTable, true /*isip6*/)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("DelDefault46RouteViaTable errored ip4:%s ip6:%s", err1, err2)
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
