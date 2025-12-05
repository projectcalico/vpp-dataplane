// Copyright (C) 2020 Cisco Systems Inc.
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

package vppmanager

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/calico-vpp-agent/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

// configureVppUplinkInterface configures one uplink interface in VPP
// and creates the corresponding tap in Linux
func (v *VppRunner) configureVppUplinkInterface(intf *params.VppManagerInterface) error {
	v.log.Infof("Creating uplink interface pid %d", v.vppProcess.Pid)
	err := intf.Driver.CreateMainVppInterface(v.vpp, v.vppProcess.Pid, &intf.Spec)
	if err != nil {
		return errors.Wrap(err, "Error creating uplink interface")
	}

	// Configure the physical network if we see it for the first time
	if _, ok := v.VppManagerInfo.PhysicalNets[intf.Spec.PhysicalNetworkName]; !ok {
		err = v.AllocatePhysicalNetworkVRFs(intf.Spec.PhysicalNetworkName)
		if err != nil {
			return err
		}
	}

	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	if *config.GetCalicoVppDebug().GSOEnabled {
		err = v.vpp.EnableGSOFeature(intf.Spec.SwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on uplink interface")
		}
	}

	uplinkMtu := vpplink.DefaultIntTo(intf.Spec.Mtu, intf.State.Mtu)
	err = v.vpp.SetInterfaceMtu(intf.Spec.SwIfIndex, uplinkMtu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on uplink interface", uplinkMtu)
	}

	err = v.vpp.SetInterfaceRxMode(intf.Spec.SwIfIndex, types.AllQueues, intf.Spec.GetRxModeWithDefault(intf.Driver.GetDefaultRxMode()))
	if err != nil {
		v.log.Warnf("%v", err)
	}

	err = v.vpp.EnableInterfaceIP6(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling ipv6 on uplink interface")
	}

	err = v.vpp.DisableIP6RouterAdvertisements(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error disabling ipv6 RA on uplink interface")
	}

	err = v.vpp.CnatEnableFeatures(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error configuring NAT on uplink interface")
	}

	if intf.Spec.PhysicalNetworkName != "" {
		for _, ipFamily := range vpplink.IPFamilies {
			err = v.vpp.SetInterfaceVRF(intf.Spec.SwIfIndex, v.VppManagerInfo.PhysicalNets[intf.Spec.PhysicalNetworkName].VrfID, ipFamily.IsIP6)
			if err != nil {
				return errors.Wrapf(err, "error setting interface in vrf %d", v.VppManagerInfo.PhysicalNets[intf.Spec.PhysicalNetworkName])
			}
		}
		value := v.VppManagerInfo.PhysicalNets[intf.Spec.PhysicalNetworkName]
		v.VppManagerInfo.PhysicalNets[intf.Spec.PhysicalNetworkName] = config.PhysicalNetwork{
			VrfID:    value.VrfID,
			PodVrfID: value.PodVrfID,
		}
	}

	// Bring the uplink interface admin-up now that all pre-configurations
	// (IPv6 RA suppression, CNAT features, VRF assignment) are complete,
	// but BEFORE adding any addresses or routes.
	//
	// If an IPv4 address is added to a DOWN interface, VPP skips creating the
	// /32 local route for the interface address, the connected/glean route for
	// the subnet and the broadcast routes. Without these routes, VPP's ARP
	// subsystem cannot function since ARP neighbor learning requires the glean
	// route to validate that the sender IP is in a connected subnet. Without
	// validation, VPP refuses to learn neighbors resulting in an empty neighbor
	// table and 100% packet loss for IPv4 traffic.
	err = v.vpp.InterfaceAdminUp(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error setting uplink interface %d admin-up", intf.Spec.SwIfIndex)
	}

	for _, addr := range intf.State.GetAddresses() {
		v.log.Infof("Adding address %s to uplink interface", addr.IPNet.String())
		err = v.vpp.AddInterfaceAddress(intf.Spec.SwIfIndex, addr.IPNet)
		if err != nil {
			return errors.Wrapf(err, "Error adding address %s to uplink interface", addr.IPNet)
		}
	}
	for _, route := range intf.State.GetRoutes() {
		err = v.vpp.RouteAdd(&types.Route{
			Dst: route.Dst,
			Paths: []types.RoutePath{{
				Gw:        route.Gw,
				SwIfIndex: intf.Spec.SwIfIndex,
			}},
		})
		if err != nil {
			v.log.Errorf("cannot add route in vpp: %v", err)
		}
	}

	gws, err := config.GetCalicoVppInitialConfig().GetDefaultGWs()
	if err != nil {
		return err
	}
	for _, defaultGW := range gws {
		v.log.Infof("Adding default route to %s", defaultGW.String())
		err = v.vpp.RouteAdd(&types.Route{
			Paths: []types.RoutePath{{
				Gw:        defaultGW,
				SwIfIndex: intf.Spec.SwIfIndex,
			}},
		})
		if err != nil {
			v.log.Errorf("cannot add default route via %s in vpp: %v", defaultGW, err)
		}
	}

	v.log.Infof("Creating Linux side interface")
	vpptap0Flags := types.TapFlagNone
	if *config.GetCalicoVppDebug().GSOEnabled {
		vpptap0Flags = vpptap0Flags | types.TapFlagGSO | types.TapGROCoalesce
	}

	tapSwIfIndex, err := v.vpp.CreateTapV2(&types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			HostInterfaceName: intf.Spec.InterfaceName,
			RxQueueSize:       config.GetCalicoVppInterfaces().VppHostTapSpec.RxQueueSize,
			TxQueueSize:       config.GetCalicoVppInterfaces().VppHostTapSpec.TxQueueSize,
			HardwareAddr:      intf.Spec.GetVppSideHardwareAddress(),
		},
		HostNamespace:  v.params.VppManagerNs,
		Tag:            "host-" + intf.Spec.InterfaceName,
		Flags:          vpptap0Flags,
		HostMtu:        uplinkMtu,
		HostMacAddress: intf.State.HardwareAddr,
	})
	if err != nil {
		return errors.Wrap(err, "Error creating tap")
	}

	intf.State.TapSwIfIndex = tapSwIfIndex

	vrfs, err := v.setupTapVRF(&intf.Spec, intf.State, tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error configuring VRF for tap")
	}

	// Always set this tap on worker 0
	err = v.vpp.SetInterfaceRxPlacement(tapSwIfIndex, 0 /*queue*/, 0 /*worker*/, false /*main*/)
	if err != nil {
		return errors.Wrap(err, "Error setting tap rx placement")
	}

	err = v.vpp.SetInterfaceMtu(uint32(tapSwIfIndex), vpplink.CalicoVppMaxMTu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on tap interface", vpplink.CalicoVppMaxMTu)
	}

	if intf.State.GetNodeIP(vpplink.IPFamilyV6) != nil {
		err = v.vpp.DisableIP6RouterAdvertisements(tapSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error disabling ip6 RA on vpptap0")
		}
		err = v.vpp.EnableIP6NdProxy(tapSwIfIndex)
		if err != nil {
			v.log.WithError(err).Errorf("Error enabling ND proxy for tap %d", tapSwIfIndex)
		}
	}
	err = v.configurePunt(tapSwIfIndex, *intf.State)
	if err != nil {
		return errors.Wrap(err, "Error adding redirect to tap")
	}
	err = v.vpp.EnableArpProxy(tapSwIfIndex, vrfs[0 /* ip4 */])
	if err != nil {
		return errors.Wrap(err, "Error enabling ARP proxy")
	}

	if *config.GetCalicoVppDebug().GSOEnabled {
		err = v.vpp.EnableGSOFeature(tapSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on vpptap0")
		}
	}

	err = v.vpp.SetInterfaceRxMode(tapSwIfIndex, types.AllQueues, config.GetCalicoVppInterfaces().VppHostTapSpec.GetRxModeWithDefault(types.AdaptativeRxMode))
	if err != nil {
		v.log.Errorf("Error SetInterfaceRxMode on vpptap0 %v", err)
	}

	err = v.vpp.CnatEnableFeatures(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error configuring NAT on vpptap0")
	}

	err = v.vpp.EnableTTLFixup(tapSwIfIndex, intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling TTL fixup on vpptap0")
	}

	// Get Linux link info for the tap, but do NOT bring it up yet.
	// Linux tap configuration (link up, addresses, routes) is performed
	// in runVPP() where we reconcile the tap link-local address in
	// configureIPv6LinkLocal() BEFORE running the VPP_RUNNING hook.
	link, err := netlink.LinkByName(intf.Spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", intf.Spec.InterfaceName)
	}

	fakeNextHopIP4, fakeNextHopIP6 := v.pickNextHopIP(*intf.State)

	v.VppManagerInfo.UplinkStatuses[link.Attrs().Name] = config.UplinkStatus{
		TapSwIfIndex:        tapSwIfIndex,
		SwIfIndex:           intf.Spec.SwIfIndex,
		Mtu:                 uplinkMtu,
		PhysicalNetworkName: intf.Spec.PhysicalNetworkName,
		LinkIndex:           link.Attrs().Index,
		Name:                link.Attrs().Name,
		IsMain:              intf.Spec.IsMain,
		FakeNextHopIP4:      fakeNextHopIP4,
		FakeNextHopIP6:      fakeNextHopIP6,
		UplinkAddresses:     intf.State.GetAddressesAsIPNet(),
	}
	return nil
}

func (v *VppRunner) configureLinuxTap(intf *params.VppManagerInterface) error {
	link, err := netlink.LinkByName(intf.Spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error finding tap interface %s", intf.Spec.InterfaceName)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	if intf.State.GetNodeIP(vpplink.IPFamilyV6) != nil {
		err := podinterface.WriteProcSys("/proc/sys/net/ipv6/conf/"+link.Attrs().Name+"/disable_ipv6", "0")
		if err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf."+link.Attrs().Name+".disable_ipv6=0: %s", err)
		}
	}
	// Configure original addresses and routes on the new tap
	for _, addr := range intf.State.GetAddressesNoMaskTranslation() {
		v.log.Infof("Adding address %+v to tap interface", addr)
		err = netlink.AddrAdd(link, &addr)
		if err == syscall.EEXIST {
			v.log.Warnf("add addr %+v via vpp EEXIST, %+v", addr, err)
		} else if err != nil {
			v.log.Errorf("Error adding address %s to tap interface: %v", addr, err)
		}
	}
	for _, route := range intf.State.GetRoutes() {
		route.LinkIndex = link.Attrs().Index
		v.log.Infof("Adding route %s via VPP", route)
		err = netlink.RouteAdd(&route)
		if err == syscall.EEXIST {
			v.log.Infof("add route via vpp : %s already exists", route)
		} else if err != nil {
			v.log.Errorf("cannot add route %+v via vpp: %v", route, err)
		}
	}

	return nil
}

// setupIPv6MulticastForHostTap configures mFIB entries to allow IPv6 multicast traffic
// from the Linux host to pass through VPP. This is required for DHCPv6, NDP, and other
// IPv6 protocols that use link-local multicast.
// Without this configuration, packets arriving from the tap interface fail RPF checks
// because the tap interface is not in the mFIB accept list.
func (v *VppRunner) setupIPv6MulticastForHostTap(vrfID uint32, tapSwIfIndex uint32, uplinkSwIfIndex uint32) error {
	v.log.Infof("Setting up IPv6 multicast forwarding for host tap in VRF %d", vrfID)

	// IPv6 multicast groups that need to be forwarded from the Linux host
	multicastGroups := []struct {
		addr    string
		prefix  int // CIDR prefix length
		comment string
	}{
		{"ff02::1:ff00:0", 104, "Solicited-Node multicast (NDP Neighbor Solicitation targets)"},
		{"ff02::1", 128, "All Nodes / All Hosts (link-local; used by NDP and others)"},
		{"ff02::2", 128, "All Routers (routers listen here; NDP RS target)"},
		{"ff02::16", 128, "All MLDv2-capable routers"},
		{"ff02::1:2", 128, "DHCPv6 All Relay Agents and Servers"},
	}

	for _, group := range multicastGroups {
		groupIP := net.ParseIP(group.addr)
		if groupIP == nil {
			v.log.Warnf("Invalid multicast address: %s", group.addr)
			continue
		}

		groupNet := &net.IPNet{
			IP:   groupIP,
			Mask: net.CIDRMask(group.prefix, 128),
		}

		err := v.vpp.MRouteAddForHostMulticast(vrfID, groupNet, tapSwIfIndex, uplinkSwIfIndex)
		if err != nil {
			return errors.Wrapf(err, "cannot add mFIB route for %s (%s) in VRF %d",
				group.addr, group.comment, vrfID)
		}

		v.log.Infof("Added mFIB route for %s (%s) in VRF %d", group.addr, group.comment, vrfID)
	}

	return nil
}

// Configure specific VRFs for a given tap to the host to handle broadcast / multicast traffic sent by the host
func (v *VppRunner) setupTapVRF(ifSpec *config.UplinkInterfaceSpec, ifState *config.LinuxInterfaceState, tapSwIfIndex uint32) (vrfs []uint32, err error) {
	for _, ipFamily := range vpplink.IPFamilies {
		vrfID, err := v.vpp.AllocateVRF(ipFamily.IsIP6, fmt.Sprintf("host-tap-%s-%s", ifSpec.InterfaceName, ipFamily.Str))
		if err != nil {
			return []uint32{}, errors.Wrap(err, "Error allocating vrf for tap")
		}
		if ipFamily.IsIP4 {
			// special route to forward broadcast from the host through the matching uplink
			// useful for instance for DHCP DISCOVER pkts from the host
			err = v.vpp.RouteAdd(&types.Route{
				Table: vrfID,
				Dst: &net.IPNet{
					IP:   net.IPv4bcast,
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
				Paths: []types.RoutePath{{
					Gw:        net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
					SwIfIndex: ifSpec.SwIfIndex,
				}},
			})
			if err != nil {
				v.log.Errorf("cannot add broadcast route in vpp: %v", err)
			}
		} else {
			// Setup IPv6 multicast forwarding for the host
			// This is required for DHCPv6 solicitations, NDP, and other link-local multicast
			// Unlike IPv4, we cannot use a unicast route trick because ff02::/16 is multicast
			// and must go through mFIB with proper RPF configuration
			err = v.setupIPv6MulticastForHostTap(vrfID, tapSwIfIndex, ifSpec.SwIfIndex)
			if err != nil {
				return []uint32{}, errors.Wrap(err, "Error setting up IPv6 multicast forwarding")
			}
		}

		// default route in default table
		err = v.vpp.AddDefaultRouteViaTable(vrfID, v.VppManagerInfo.PhysicalNets[ifSpec.PhysicalNetworkName].VrfID, ipFamily.IsIP6)
		if err != nil {
			return []uint32{}, errors.Wrapf(err, "error adding VRF %d default route via VRF %d", vrfID, v.VppManagerInfo.PhysicalNets[ifSpec.PhysicalNetworkName])
		}
		// Set tap in this table
		err = v.vpp.SetInterfaceVRF(tapSwIfIndex, vrfID, ipFamily.IsIP6)
		if err != nil {
			return []uint32{}, errors.Wrapf(err, "error setting vpp tap in vrf %d", vrfID)
		}
		vrfs = append(vrfs, vrfID)

		for _, addr := range ifState.GetAddressesNoMaskTranslation() {
			if vpplink.IPFamilyFromIP(addr.IP) == ipFamily {
				err = v.vpp.RouteAdd(&types.Route{
					Table: vrfID,
					Dst:   common.FullyQualified(addr.IP),
					Paths: []types.RoutePath{{
						Gw:        addr.IP,
						SwIfIndex: tapSwIfIndex,
					}},
				})
				if err != nil {
					return []uint32{}, errors.Wrapf(err, "error add route from VPP to tap0 in VRF %d", vrfID)
				}
				err = v.vpp.AddNeighbor(&types.Neighbor{
					SwIfIndex:    tapSwIfIndex,
					IP:           addr.IP,
					HardwareAddr: ifState.HardwareAddr,
					Flags:        types.IPNeighborStatic,
				})
				if err != nil {
					return []uint32{}, errors.Wrapf(err, "error add static neighbor for tap0 in VRF %d", vrfID)
				}
			}
		}
	}

	err = v.vpp.EnableInterfaceIP6(tapSwIfIndex)
	if err != nil {
		return []uint32{}, errors.Wrapf(err, "error enabling ip6 for tap %d", tapSwIfIndex)
	}

	err = v.vpp.AddInterfaceAddress(tapSwIfIndex, config.VppsideTap0Address)
	if err != nil {
		return []uint32{}, errors.Wrapf(err, "error adding vpp side address for tap0 %d", tapSwIfIndex)
	}
	return vrfs, nil
}

// pick a next hop to use for cluster routes (services, pod cidrs) in the address prefix
func (v *VppRunner) pickNextHopIP(ifState config.LinuxInterfaceState) (fakeNextHopIP4, fakeNextHopIP6 net.IP) {
	fakeNextHopIP4 = net.ParseIP("0.0.0.0")
	fakeNextHopIP6 = net.ParseIP("::")
	var nhAddr net.IP
	foundV4, foundV6 := false, false
	needsV4, needsV6 := false, false

	addrs := ifState.GetAddressesNoMaskTranslation()
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			needsV4 = true
		} else {
			needsV6 = true
		}
	}

	// #1 Prefer the real default-route gateway. If a stale cluster route pointing
	// at the real gateway survives a crash/restore cycle and is re-programmed into
	// VPP via the uplink, VPP can still ARP-resolve it and prevent UNRESOLVED FIB
	// entries that would silently drop all pod-CIDR traffic. A default route can be
	// represented as Dst == nil or Dst == 0.0.0.0/0 (::/0) in netlink.
	for _, route := range ifState.GetRoutes() {
		if !config.IsDefaultRoute(route.Dst) || route.Gw == nil {
			continue
		}
		gw := route.Gw
		isV4 := gw.To4() != nil
		if isV4 && foundV4 {
			continue
		}
		if !isV4 && foundV6 {
			continue
		}
		if isV4 {
			v.log.Infof("Using default route gateway %s as next hop for cluster IPv4 routes", gw)
			fakeNextHopIP4 = gw
			foundV4 = true
		} else {
			v.log.Infof("Using default route gateway %s as next hop for cluster IPv6 routes", gw)
			fakeNextHopIP6 = gw
			foundV6 = true
		}
	}

	if (!needsV4 || foundV4) && (!needsV6 || foundV6) {
		return
	}

	// #2 Derive a synthetic next hop from the interface's own address subnet
	for _, addr := range addrs {
		nhAddr = config.DecrementIP(config.BroadcastAddr(addr.IPNet))
		if nhAddr.Equal(addr.IP) {
			nhAddr = config.IncrementIP(config.NetworkAddr(addr.IPNet))
		}
		if !addr.Contains(nhAddr) {
			continue
		}
		if nhAddr.To4() != nil {
			if !foundV4 {
				v.log.Infof("Using %s as next hop for cluster IPv4 routes", nhAddr.String())
				fakeNextHopIP4 = nhAddr
				foundV4 = true
			}
		} else {
			if !foundV6 {
				v.log.Infof("Using %s as next hop for cluster IPv6 routes", nhAddr.String())
				fakeNextHopIP6 = nhAddr
				foundV6 = true
			}
		}
	}

	if (!needsV4 || foundV4) && (!needsV6 || foundV6) {
		return
	}

	// #3 Use directly connected routes (Gw == nil, Dst != nil).
	for _, route := range ifState.GetRoutes() {
		if route.Gw != nil || route.Dst == nil {
			continue
		}
		if (route.Dst.IP.To4() != nil && foundV4) || (route.Dst.IP.To4() == nil && foundV6) {
			continue
		}
		ones, _ := route.Dst.Mask.Size()
		if route.Dst.IP.To4() != nil {
			if ones == 32 {
				v.log.Infof("Using %s as next hop for cluster IPv4 routes (from directly connected /32 route)", route.Dst.IP.String())
				fakeNextHopIP4 = route.Dst.IP
				foundV4 = true
			} else {
				// pick an address in the subnet
				nhAddr = config.DecrementIP(config.BroadcastAddr(route.Dst))
				if ifState.HasAddr(nhAddr) {
					nhAddr = config.IncrementIP(config.NetworkAddr(route.Dst))
				}
				v.log.Infof("Using %s as next hop for cluster IPv4 routes (from directly connected route)", nhAddr.String())
				fakeNextHopIP4 = nhAddr
				foundV4 = true
			}
		} else {
			if ones == 128 {
				v.log.Infof("Using %s as next hop for cluster IPv6 routes (from directly connected /128 route)", route.Dst.IP.String())
				fakeNextHopIP6 = route.Dst.IP
				foundV6 = true
			} else {
				// pick an address in the subnet
				nhAddr = config.DecrementIP(config.BroadcastAddr(route.Dst))
				if ifState.HasAddr(nhAddr) {
					nhAddr = config.IncrementIP(config.NetworkAddr(route.Dst))
				}
				v.log.Infof("Using %s as next hop for cluster IPv6 routes (from directly connected route)", nhAddr.String())
				fakeNextHopIP6 = nhAddr
				foundV6 = true
			}
		}
	}
	return
}

func (v *VppRunner) AllocatePhysicalNetworkVRFs(phyNet string) (err error) {
	// for ip4
	mainVrfID, err := v.vpp.AllocateVRF(false, fmt.Sprintf("physical-net-%s-ip4", phyNet))
	if err != nil {
		return err
	}
	podVrfID, err := v.vpp.AllocateVRF(false, fmt.Sprintf("calico-pods-%s-ip4", phyNet))
	if err != nil {
		return err
	}
	// for ip6, use same vrfID as ip4
	err = v.vpp.AddVRF(mainVrfID, true, fmt.Sprintf("physical-net-%s-ip6", phyNet))
	if err != nil {
		return err
	}
	err = v.vpp.AddVRF(podVrfID, true, fmt.Sprintf("calico-pods-%s-ip6", phyNet))
	if err != nil {
		return err
	}
	for _, ipFamily := range vpplink.IPFamilies {
		err = v.vpp.AddDefaultRouteViaTable(podVrfID, mainVrfID, ipFamily.IsIP6)
		if err != nil {
			return err
		}
	}
	v.VppManagerInfo.PhysicalNets[phyNet] = config.PhysicalNetwork{VrfID: mainVrfID, PodVrfID: podVrfID}
	return nil
}

// configurePunt adds in VPP in the punt table routes to the tap.
// traffic 'for me' received on the PHY and on the pods in this node
// will end up here.
func (v *VppRunner) configurePunt(tapSwIfIndex uint32, ifState config.LinuxInterfaceState) (err error) {
	for _, addr := range ifState.GetAddressesNoMaskTranslation() {
		err = v.vpp.RouteAdd(&types.Route{
			Table: config.PuntTableID,
			Dst:   addr.IPNet,
			Paths: []types.RoutePath{{
				Gw:        addr.IP,
				SwIfIndex: tapSwIfIndex,
			}},
		})
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		}
	}
	return nil
}

// configureIPv6LinkLocal discovers the IPv6 link-local address for the tap
// interface and configures the associated VPP routes and proxy entries.
// This MUST be called AFTER configureLinuxTap() has brought the tap UP,
// because the kernel only generates the link-local address on NETDEV_UP
// (via addrconf_notify). Calling it earlier would race with address
// generation and intermittently fail, leaving the punt table without a
// /128 entry for the link-local address. Without that entry, punted
// link-local traffic (e.g. DHCPv6 on UDP/546) matches the built-in
// fe80::/10 → ip6-link-local DPO, which redirects packets back to the
// per-interface link-local FIB, creating a receive → punt → redirect →
// ip6-link-local → receive loop that VPP drops after 5 iterations.
func (v *VppRunner) configureIPv6LinkLocal(intf *params.VppManagerInterface) (err error) {
	var link netlink.Link
	// tapV6LLAddr is the LL address linux auto-assigns to the tap
	// after its creation
	var tapV6LLAddr *netlink.Addr
	// phyV6LLAddr is the first LL address seen the PHY before startup
	phyV6LLAddr := intf.State.GetIPv6LinkLocal()

	if intf.State.GetNodeIP(vpplink.IPFamilyV6) == nil {
		return nil
	}

	if phyV6LLAddr == nil {
		return errors.Errorf("no LL address found for interface %s", intf.Spec.InterfaceName)
	}

	// Poll for the link-local address. The tap is already UP so the kernel
	// should assign it within a few seconds (typically < 1s, DAD may add ~1s).
	for i := uint32(0); i < *config.GetCalicoVppDebug().FetchV6LLntries; i++ {
		time.Sleep(time.Second)
		link, err = netlink.LinkByName(intf.Spec.InterfaceName)
		if err != nil {
			v.log.WithError(err).Warnf("configureIPv6LinkLocal: cannot find interface %s", intf.Spec.InterfaceName)
			continue
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			v.log.WithError(err).Warnf("configureIPv6LinkLocal: could not list v6 addresses on %s", intf.Spec.InterfaceName)
			continue
		}
		for _, addr := range addresses {
			if addr.IP.IsLinkLocalUnicast() {
				tapV6LLAddr = &addr
				goto found
			}
		}
	}

	return errors.Errorf("could not find v6 LL address for %s after %ds",
		intf.Spec.InterfaceName, *config.GetCalicoVppDebug().FetchV6LLntries)

found:
	v.log.Infof("removing tap-ll:%s using phy-ll:%s for %s", tapV6LLAddr, phyV6LLAddr, intf.Spec.InterfaceName)
	if !tapV6LLAddr.IP.Equal(phyV6LLAddr.IP) {
		err = netlink.AddrAdd(link, phyV6LLAddr)
		if err == syscall.EEXIST {
			v.log.Warnf("add addr %s via vpp EEXIST, %+v", phyV6LLAddr, err)
		} else if err != nil {
			return errors.Wrapf(err, "error adding address %s to tap interface %s", phyV6LLAddr, intf.Spec.InterfaceName)
		}

		err = netlink.AddrDel(link, tapV6LLAddr)
		if err != nil {
			return errors.Wrapf(err, "error deleting address %s from tap interface %s", tapV6LLAddr, intf.Spec.InterfaceName)
		}
	}

	err = v.vpp.AddNeighbor(&types.Neighbor{
		SwIfIndex:    intf.State.TapSwIfIndex,
		IP:           phyV6LLAddr.IP,
		HardwareAddr: intf.State.HardwareAddr,
		Flags:        types.IPNeighborStatic,
	})
	if err != nil {
		return errors.Wrapf(err, "error add static neighbor for %s tap0 %d", phyV6LLAddr.IP, intf.State.TapSwIfIndex)
	}
	// Add LL /128 route to punt table so that punted link-local traffic
	// reaches the host via tap instead of hitting fe80::/10 → ip6-link-local.
	err = v.vpp.RouteAdd(&types.Route{
		Table: config.PuntTableID,
		Dst:   common.FullyQualified(phyV6LLAddr.IP),
		Paths: []types.RoutePath{{
			Gw:        phyV6LLAddr.IP,
			SwIfIndex: intf.State.TapSwIfIndex,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "error adding LL punt route for %s", intf.Spec.InterfaceName)
	}

	// Add LL address to the uplink interface
	err = v.vpp.AddInterfaceAddress(intf.Spec.SwIfIndex, common.FullyQualified(phyV6LLAddr.IP))
	if err != nil {
		return errors.Wrapf(err, "Error adding LL address %s to uplink interface %d",
			common.FullyQualified(phyV6LLAddr.IP), intf.Spec.SwIfIndex)
	}

	return nil
}
