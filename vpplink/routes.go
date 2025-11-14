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
	vppip "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/mfib_types"
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

func (v *VppLink) MRouteAdd(route *types.Route, flags mfib_types.MfibEntryFlags) error {
	return v.addDelIPMRoute(route, flags, true)
}

func (v *VppLink) MRouteDel(route *types.Route, flags mfib_types.MfibEntryFlags) error {
	return v.addDelIPMRoute(route, flags, false)
}

func (v *VppLink) addDelIPMRoute(route *types.Route, flags mfib_types.MfibEntryFlags, isAdd bool) error {
	client := vppip.NewServiceClient(v.GetConnection())

	isIP6 := route.IsIP6()
	ones, _ := route.Dst.Mask.Size()
	prefix := ip_types.Mprefix{
		Af:               types.ToVppAddressFamily(isIP6),
		GrpAddressLength: uint16(ones),
		GrpAddress:       types.ToVppAddress(route.Dst.IP).Un,
		// we do not expose SrcAddress yet
	}

	paths := make([]mfib_types.MfibPath, 0, len(route.Paths))
	for _, routePath := range route.Paths {
		paths = append(paths, mfib_types.MfibPath{
			ItfFlags: mfib_types.MFIB_API_ITF_FLAG_FORWARD,
			Path:     routePath.ToFibPath(isIP6),
		})

	}

	vppRoute := vppip.IPMroute{
		TableID:    uint32(route.Table),
		Prefix:     prefix,
		EntryFlags: flags,
		Paths:      paths,
		RpfID:      route.RpfID,
	}

	_, err := client.IPMrouteAddDel(v.GetContext(), &vppip.IPMrouteAddDel{
		IsAdd: isAdd,
		Route: vppRoute,
	})
	if err != nil {
		return fmt.Errorf("failed to %s mroute from VPP: %w", IsAddToStr(isAdd), err)
	}
	v.GetLog().Debugf("%sed mroute %+v", IsAddToStr(isAdd), route)
	return nil
}

// MRouteAddForHostMulticast adds an mFIB route with explicit interface flags for each path
// This is needed for forwarding multicast traffic like DHCPv6 solicitations from the host
// For DHCPv6 from Linux host via tap:
// - tapSwIfIndex should have ACCEPT flag (allow packets from tap)
// - uplinkSwIfIndex should have ACCEPT|FORWARD flags (forward to uplink, accept replies)
func (v *VppLink) MRouteAddForHostMulticast(tableID uint32, group *net.IPNet, tapSwIfIndex, uplinkSwIfIndex uint32) error {
	client := vppip.NewServiceClient(v.GetConnection())

	isIP6 := group.IP.To4() == nil
	ones, _ := group.Mask.Size()
	prefix := ip_types.Mprefix{
		Af:               types.ToVppAddressFamily(isIP6),
		GrpAddressLength: uint16(ones),
		GrpAddress:       types.ToVppAddress(group.IP).Un,
		// SrcAddress is all zeros for (*,G) entries
	}

	// Create mFIB paths with explicit interface flags
	paths := []mfib_types.MfibPath{
		{
			// Uplink interface: Accept + Forward
			// Accept incoming multicast from network, forward outgoing multicast to network
			ItfFlags: mfib_types.MFIB_API_ITF_FLAG_ACCEPT | mfib_types.MFIB_API_ITF_FLAG_FORWARD,
			Path: fib_types.FibPath{
				SwIfIndex:  uplinkSwIfIndex,
				TableID:    0,
				RpfID:      0,
				Weight:     1,
				Preference: 0,
				Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
				Flags:      fib_types.FIB_API_PATH_FLAG_NONE,
				Proto:      types.IsV6toFibProto(isIP6),
			},
		},
		{
			// Tap interface: Accept only
			// This allows packets FROM Linux host to pass RPF check
			ItfFlags: mfib_types.MFIB_API_ITF_FLAG_ACCEPT,
			Path: fib_types.FibPath{
				SwIfIndex:  tapSwIfIndex,
				TableID:    0,
				RpfID:      0,
				Weight:     1,
				Preference: 0,
				Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
				Flags:      fib_types.FIB_API_PATH_FLAG_NONE,
				Proto:      types.IsV6toFibProto(isIP6),
			},
		},
	}

	vppRoute := vppip.IPMroute{
		TableID:    tableID,
		Prefix:     prefix,
		EntryFlags: mfib_types.MFIB_API_ENTRY_FLAG_NONE, // Use interface-based RPF, not ACCEPT_ALL_ITF
		Paths:      paths,
		RpfID:      0, // No RPF-ID, use interface-based checking
	}

	_, err := client.IPMrouteAddDel(v.GetContext(), &vppip.IPMrouteAddDel{
		IsAdd: true,
		Route: vppRoute,
	})
	if err != nil {
		return fmt.Errorf("failed to add mroute for host multicast %s in table %d: %w", group.String(), tableID, err)
	}

	v.GetLog().Infof("Added mFIB route for host multicast %s in table %d (tap=%d, uplink=%d)",
		group.String(), tableID, tapSwIfIndex, uplinkSwIfIndex)
	return nil
}

func (v *VppLink) addDelDefaultMRouteViaTable(srcTable, dstTable uint32, isIP6 bool, isAdd bool) error {
	route := &types.Route{
		Paths: []types.RoutePath{{
			Table:     dstTable,
			SwIfIndex: types.InvalidID,
			// we add a RpfID matching the srcTable so that we lookup in the multicast table
			RpfID: srcTable,
		}},
		Table: srcTable,
		RpfID: 0,
	}
	// Use the mcast CIDRs of the ip family
	if isIP6 {
		_, c, _ := net.ParseCIDR("ff00::/8")
		route.Dst = c
	} else {
		_, c, _ := net.ParseCIDR("224.0.0.0/4")
		route.Dst = c
	}
	return v.addDelIPMRoute(route, mfib_types.MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF, isAdd /*isAdd*/)
}

func (v *VppLink) AddDefaultMRouteViaTable(sourceTable, dstTable uint32, isIP6 bool) error {
	return v.addDelDefaultMRouteViaTable(sourceTable, dstTable, isIP6, true /*isAdd*/)
}

func (v *VppLink) DelDefaultMRouteViaTable(sourceTable, dstTable uint32, isIP6 bool) error {
	return v.addDelDefaultMRouteViaTable(sourceTable, dstTable, isIP6, false /*isAdd*/)
}
