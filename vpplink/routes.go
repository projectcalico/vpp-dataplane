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
	"io"
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/fib_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	vppip "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_neighbor"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) GetRoutes(tableID uint32, isIPv6 bool) ([]types.Route, error) {
	client := vppip.NewServiceClient(v.GetConnection())

	stream, err := client.IPRouteDump(v.GetContext(), &vppip.IPRouteDump{
		Table: vppip.IPTable{
			TableID: tableID,
			IsIP6:   isIPv6,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump VPP routes: %w", err)
	}
	var routes []types.Route
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump VPP routes: %w", err)
		}
		route := types.Route{
			Dst:   types.FromVppPrefix(response.Route.Prefix),
			Table: response.Route.TableID,
			Paths: types.FromFibPathList(response.Route.Paths),
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func (v *VppLink) AddNeighbor(neighbor *types.Neighbor) error {
	return v.addDelNeighbor(neighbor, true)
}

func (v *VppLink) DelNeighbor(neighbor *types.Neighbor) error {
	return v.addDelNeighbor(neighbor, false)
}

func (v *VppLink) addDelNeighbor(neighbor *types.Neighbor, isAdd bool) error {
	client := ip_neighbor.NewServiceClient(v.GetConnection())

	_, err := client.IPNeighborAddDel(v.GetContext(), &ip_neighbor.IPNeighborAddDel{
		IsAdd: isAdd,
		Neighbor: ip_neighbor.IPNeighbor{
			SwIfIndex:  interface_types.InterfaceIndex(neighbor.SwIfIndex),
			Flags:      types.ToVppNeighborFlags(neighbor.Flags),
			MacAddress: types.MacAddress(neighbor.HardwareAddr),
			IPAddress:  types.ToVppAddress(neighbor.IP),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to %s neighbor from VPP: %w", isAddStr(isAdd), err)
	}
	v.GetLog().Debugf("%sed neighbor %+v", isAddStr(isAdd), neighbor)
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
			return fmt.Errorf("failed to add route in VPP: %w", err)
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
	client := vppip.NewServiceClient(v.GetConnection())

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
		TableID: route.Table,
		Prefix:  prefix,
		Paths:   paths,
	}

	_, err := client.IPRouteAddDel(v.GetContext(), &vppip.IPRouteAddDel{
		IsAdd: isAdd,
		Route: vppRoute,
	})
	if err != nil {
		return fmt.Errorf("failed to %s route from VPP: %w", IsAddToStr(isAdd), err)
	}
	v.GetLog().Debugf("%sed route %+v", IsAddToStr(isAdd), route)
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

func (v *VppLink) SetIPFlowHash(ipFlowHash types.IPFlowHash, vrfID uint32, isIPv6 bool) error {
	client := vppip.NewServiceClient(v.GetConnection())

	_, err := client.SetIPFlowHashV2(v.GetContext(), &vppip.SetIPFlowHashV2{
		TableID:        vrfID,
		Af:             types.GetBoolIPFamily(isIPv6),
		FlowHashConfig: vppip.IPFlowHashConfig(ipFlowHash),
	})
	if err != nil {
		return fmt.Errorf("failed to update flow hash algo for vrf %d: %w", vrfID, err)
	}
	v.GetLog().Debugf("updated flow hash algo for vrf %d", vrfID)
	return nil
}
