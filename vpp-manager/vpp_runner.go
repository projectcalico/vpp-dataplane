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

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	calicoopts "github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type VppRunner struct {
	params *config.VppManagerParams
	vpp    *vpplink.VppLink
}

func NewVPPRunner(params *config.VppManagerParams) *VppRunner {
	return &VppRunner{
		params: params,
	}
}

func (v *VppRunner) Run() error {
	for interfaceName, intf := range v.params.Interfaces {
		log.Infof("Running interface %s with uplink %s", interfaceName, intf.Driver.GetName())
	}
	template, err := config.TemplateScriptReplace(*config.ConfigExecTemplate, v.params)
	if err != nil {
		return errors.Wrap(err, "Error generating VPP config exec file")
	}
	err = os.WriteFile(config.VppConfigExecFile, []byte(template+"\n"), 0744)
	if err != nil {
		return errors.Wrapf(err, "Error writing VPP config exec file to %s", config.VppConfigExecFile)
	}

	template, err = config.TemplateScriptReplace(*config.ConfigTemplate, v.params)
	if err != nil {
		return errors.Wrap(err, "Error generating VPP config file")
	}
	for _, intf := range v.params.Interfaces {
		template = intf.Driver.UpdateVppConfigFile(template)
	}
	err = os.WriteFile(config.VppConfigFile, []byte(template+"\n"), 0644)
	if err != nil {
		return errors.Wrapf(err, "Error writing VPP config file to %s", config.VppConfigFile)
	}

	for _, intf := range v.params.Interfaces {
		err = intf.Driver.PreconfigureLinux()
		if err != nil {
			return errors.Wrapf(err, "Error pre-configuring Linux main IF: %s", intf.Driver.GetName())
		}
	}

	networkHook.ExecuteWithUserScript(hooks.HookBeforeVppRun, config.HookScriptBeforeVppRun)

	err = v.runVpp()
	if err != nil {
		return errors.Wrapf(err, "Error running VPP")
	}

	networkHook.ExecuteWithUserScript(hooks.HookVppDoneOk, config.HookScriptVppDoneOk)
	return nil
}

func (v *VppRunner) hasAddr(ip net.IP, ifState config.LinuxInterfaceState) bool {
	for _, addr := range ifState.Addresses {
		if ip.Equal(addr.IP) {
			return true
		}
	}
	return false
}

// pick a next hop to use for cluster routes (services, pod cidrs) in the address prefix
func (v *VppRunner) pickNextHopIP(ifState config.LinuxInterfaceState) (fakeNextHopIP4, fakeNextHopIP6 net.IP) {
	fakeNextHopIP4 = net.ParseIP("0.0.0.0")
	fakeNextHopIP6 = net.ParseIP("::")
	var nhAddr net.IP
	foundV4, foundV6 := false, false
	needsV4, needsV6 := false, false

	for _, addr := range ifState.Addresses {
		if nhAddr.To4() != nil {
			needsV4 = true
		} else {
			needsV6 = true
		}
		nhAddr = utils.DecrementIP(utils.BroadcastAddr(addr.IPNet))
		if nhAddr.Equal(addr.IP) {
			nhAddr = utils.IncrementIP(utils.NetworkAddr(addr.IPNet))
		}
		if !addr.Contains(nhAddr) {
			continue
		}
		if nhAddr.To4() != nil && !foundV4 {
			log.Infof("Using %s as next hop for cluster IPv4 routes", nhAddr.String())
			fakeNextHopIP4 = nhAddr
			foundV4 = true
		} else if !nhAddr.IsLinkLocalUnicast() && !foundV6 {
			log.Infof("Using %s as next hop for cluster IPv6 routes", nhAddr.String())
			fakeNextHopIP6 = nhAddr
			foundV6 = true
		}
	}

	if !((needsV4 && !foundV4) || (needsV6 && !foundV6)) { //nolint:staticcheck
		return
	}

	for _, route := range ifState.Routes {
		if route.Gw != nil || route.Dst == nil {
			// We're looking for a directly connected route
			continue
		}
		if (route.Dst.IP.To4() != nil && foundV4) || (route.Dst.IP.To4() == nil && foundV6) || route.Dst.IP.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := route.Dst.Mask.Size()
		if route.Dst.IP.To4() != nil {
			if ones == 32 {
				log.Infof("Using %s as next hop for cluster IPv4 routes (from directly connected /32 route)", route.Dst.IP.String())
				fakeNextHopIP4 = route.Dst.IP
				foundV4 = true
			} else {
				// pick an address in the subnet
				nhAddr = utils.DecrementIP(utils.BroadcastAddr(route.Dst))
				if v.hasAddr(nhAddr, ifState) {
					nhAddr = utils.IncrementIP(utils.NetworkAddr(route.Dst))
				}
				log.Infof("Using %s as next hop for cluster IPv4 routes (from directly connected route)", route.Dst.IP.String())
				fakeNextHopIP4 = nhAddr
				foundV4 = true
			}
		}
		if route.Dst.IP.To4() == nil {
			if ones == 128 {
				log.Infof("Using %s as next hop for cluster IPv6 routes (from directly connected /128 route)", route.Dst.IP.String())
				fakeNextHopIP6 = route.Dst.IP
				foundV6 = true
			} else {
				// pick an address in the subnet
				nhAddr = utils.DecrementIP(utils.BroadcastAddr(route.Dst))
				if v.hasAddr(nhAddr, ifState) {
					nhAddr = utils.IncrementIP(utils.NetworkAddr(route.Dst))
				}
				log.Infof("Using %s as next hop for cluster IPv6 routes (from directly connected route)", route.Dst.IP.String())
				fakeNextHopIP6 = nhAddr
				foundV6 = true
			}
		}
	}
	return
}

func (v *VppRunner) configureLinuxTap(link netlink.Link, ifState config.LinuxInterfaceState) (fakeNextHopIP4, fakeNextHopIP6 net.IP, err error) {
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error setting tap up")
	}

	for _, addr := range ifState.Addresses {
		if addr.IP.To4() == nil {
			if err = podinterface.WriteProcSys("/proc/sys/net/ipv6/conf/"+link.Attrs().Name+"/disable_ipv6", "0"); err != nil {
				return nil, nil, fmt.Errorf("failed to set net.ipv6.conf."+link.Attrs().Name+".disable_ipv6=0: %s", err)
			}
			break
		}
	}
	// Configure original addresses and routes on the new tap
	for _, addr := range ifState.Addresses {
		log.Infof("Adding address %+v to tap interface", addr)
		err = netlink.AddrAdd(link, &addr)
		if err == syscall.EEXIST {
			log.Warnf("add addr %+v via vpp EEXIST, %+v", addr, err)
		} else if err != nil {
			log.Errorf("Error adding address %s to tap interface: %v", addr, err)
		}
	}
	for _, route := range ifState.Routes {
		route.LinkIndex = link.Attrs().Index
		log.Infof("Adding route %s via VPP", route)
		err = netlink.RouteAdd(&route)
		if err == syscall.EEXIST {
			log.Infof("add route via vpp : %s already exists", route)
		} else if err != nil {
			log.Errorf("cannot add route %+v via vpp: %v", route, err)
		}
	}

	// Determine a suitable next hop for the cluster routes
	fakeNextHopIP4, fakeNextHopIP6 = v.pickNextHopIP(ifState)
	return fakeNextHopIP4, fakeNextHopIP6, nil
}

// setupIPv6MulticastForHostTap configures mFIB entries to allow IPv6 multicast traffic
// from the Linux host to pass through VPP. This is required for DHCPv6, NDP, and other
// IPv6 protocols that use link-local multicast.
// Without this configuration, packets arriving from the tap interface fail RPF checks
// because the tap interface is not in the mFIB accept list.
func (v *VppRunner) setupIPv6MulticastForHostTap(vrfID uint32, tapSwIfIndex uint32, uplinkSwIfIndex uint32) error {
	log.Debugf("Setting up IPv6 multicast forwarding for host tap in VRF %d", vrfID)

	// IPv6 multicast groups that need to be forwarded from the Linux host
	multicastGroups := []struct {
		addr    net.IP
		comment string
	}{
		{net.ParseIP("ff02::1:2"), "DHCPv6 All Relay Agents and Servers (REQUIRED for DHCPv6)"},
		{net.ParseIP("ff02::1"), "All Nodes (for NDP)"},
		{net.ParseIP("ff02::2"), "All Routers (for NDP/RA)"},
	}

	for _, group := range multicastGroups {
		groupNet := &net.IPNet{
			IP:   group.addr,
			Mask: net.CIDRMask(128, 128), // /128 - specific group
		}
		err := v.vpp.MRouteAddForHostMulticast(vrfID, groupNet, tapSwIfIndex, uplinkSwIfIndex)
		if err != nil {
			return errors.Wrapf(err, "cannot add mFIB route for %s (%s) in VRF %d",
				group.addr, group.comment, vrfID)
		}
		log.Infof("added mFIB route for %s (%s) in VRF %d", group.addr, group.comment, vrfID)
	}

	return nil
}

// configureVppUplinkInterface configures one uplink interface in VPP
// and creates the corresponding tap in Linux
func (v *VppRunner) configureVppUplinkInterface(intf *config.VppManagerInterface) error {
	err := intf.Driver.CreateMainVppInterface(
		v.vpp,
		vppProcess.Pid,
		&intf.Spec,
	)
	if err != nil {
		return errors.Wrap(err, "Error creating uplink interface")
	}

	// Data interface configuration
	err = v.vpp.Retry(2*time.Second, 10, v.vpp.InterfaceAdminUp, intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error setting uplink interface up")
	}

	// Configure the physical network if we see it for the first time
	if _, found := config.Info.PhysicalNets[intf.Spec.PhysicalNetworkName]; !found {
		physicalNetwork, err := v.allocatePhysicalNetworkVRFs(intf.Spec.PhysicalNetworkName)
		if err != nil {
			return errors.Wrapf(err, "error creating physical network %s for uplink if %s", intf.Spec.PhysicalNetworkName, intf.Spec.InterfaceName)
		}
		log.Infof("created VRF vrfId=%d podVrfId=%d", physicalNetwork.VrfID, physicalNetwork.PodVrfID)
		config.Info.PhysicalNets[intf.Spec.PhysicalNetworkName] = *physicalNetwork
	}

	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	if *config.GetCalicoVppDebug().GSOEnabled {
		err = v.vpp.EnableGSOFeature(intf.Spec.SwIfIndex)
		if err != nil {
			return errors.Wrapf(err, "error enabling GSO on uplink if %s", intf.Spec.InterfaceName)
		}
	}

	uplinkMtu := vpplink.DefaultIntTo(intf.Spec.Mtu, intf.State.Mtu)
	err = v.vpp.SetInterfaceMtu(intf.Spec.SwIfIndex, uplinkMtu)
	if err != nil {
		return errors.Wrapf(err, "error setting mtu=%d on uplink if %s", uplinkMtu, intf.Spec.InterfaceName)
	}

	err = v.vpp.SetInterfaceRxMode(intf.Spec.SwIfIndex, types.AllQueues, intf.Spec.GetRxModeWithDefault(intf.Driver.GetDefaultRxMode()))
	if err != nil {
		log.Warnf("%v", err)
	}

	err = v.vpp.EnableInterfaceIP6(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error enabling ip6 on uplink if %s", intf.Spec.InterfaceName)
	}

	err = v.vpp.DisableIP6RouterAdvertisements(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error disabling ip6 RA on uplink if %s", intf.Spec.InterfaceName)
	}

	err = v.vpp.CnatEnableFeatures(intf.Spec.SwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error enabling NAT on uplink if %s", intf.Spec.InterfaceName)
	}

	for _, ipFamily := range vpplink.IPFamilies {
		err = v.vpp.SetInterfaceVRF(
			intf.Spec.SwIfIndex,
			config.Info.PhysicalNets[intf.Spec.PhysicalNetworkName].VrfID,
			ipFamily.IsIP6,
		)
		if err != nil {
			return errors.Wrapf(err, "error setting uplink if %s in vrf %d", intf.Spec.InterfaceName, config.Info.PhysicalNets[intf.Spec.PhysicalNetworkName])
		}
	}

	for _, addr := range intf.State.Addresses {
		if addr.IP.IsLinkLocalUnicast() && !common.IsFullyQualified(addr.IPNet) && common.IsV6Cidr(addr.IPNet) {
			log.Infof("Not adding address %s to uplink interface (vpp requires /128 link-local)", addr.String())
			continue
		} else {
			log.Infof("Adding address %s to uplink interface", addr.String())
		}
		err = v.vpp.AddInterfaceAddress(intf.Spec.SwIfIndex, addr.IPNet)
		if err != nil {
			log.Errorf("Error adding address to uplink interface: %v", err)
		}
	}
	for _, route := range intf.State.Routes {
		err = v.vpp.RouteAdd(&types.Route{
			Dst: route.Dst,
			Paths: []types.RoutePath{{
				Gw:        route.Gw,
				SwIfIndex: intf.Spec.SwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("error adding route in vpp: %v", err)
		}
	}

	gws, err := config.GetCalicoVppInitialConfig().GetDefaultGWs()
	if err != nil {
		return err
	}
	for _, defaultGW := range gws {
		log.Infof("Adding default route to %s", defaultGW.String())
		err = v.vpp.RouteAdd(&types.Route{
			Paths: []types.RoutePath{{
				Gw:        defaultGW,
				SwIfIndex: intf.Spec.SwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("cannot add default route via %s in vpp: %v", defaultGW, err)
		}
	}

	log.Infof("Creating Linux side interface")
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
		HostNamespace:  "pid:1", // create tap in root netns
		Tag:            "host-" + intf.Spec.InterfaceName,
		Flags:          vpptap0Flags,
		HostMtu:        uplinkMtu,
		HostMacAddress: intf.State.HardwareAddr,
	})
	if err != nil {
		return errors.Wrapf(err, "Error creating tap %s", intf.Spec.InterfaceName)
	}

	// Configure specific VRFs for a given tap to the host to handle broadcast / multicast traffic sent by the host
	for _, ipFamily := range vpplink.IPFamilies {
		vrfID, err := v.vpp.AllocateVRF(ipFamily.IsIP6, fmt.Sprintf("host-tap-%s-%s", intf.Spec.InterfaceName, ipFamily.Str))
		if err != nil {
			return errors.Wrapf(err, "error allocating %s vrf for if %s", ipFamily.Str, intf.Spec.InterfaceName)
		}
		// default route in default table
		err = v.vpp.AddDefaultRouteViaTable(vrfID, config.Info.PhysicalNets[intf.Spec.PhysicalNetworkName].VrfID, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "error adding %s VRF %d default route via VRF %d", ipFamily.Str, vrfID, config.Info.PhysicalNets[intf.Spec.PhysicalNetworkName])
		}
		// Set tap in this table
		err = v.vpp.SetInterfaceVRF(tapSwIfIndex, vrfID, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "error setting vpp tap in %s vrf %d", ipFamily.Str, vrfID)
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
					SwIfIndex: intf.Spec.SwIfIndex,
				}},
			})
			if err != nil {
				return errors.Wrapf(err, "error add broadcast route for tap %d in v4 VRF %d", tapSwIfIndex, vrfID)
			}
			err = v.vpp.EnableArpProxy(tapSwIfIndex, vrfID)
			if err != nil {
				return errors.Wrapf(err, "error enabling ARP proxy for tap %d in v4 VRF %d", tapSwIfIndex, vrfID)
			}
		} else {
			// Setup IPv6 multicast forwarding for the host
			// This is required for DHCPv6 solicitations, NDP, and other link-local multicast
			// Unlike IPv4, we cannot use a unicast route trick because ff02::/16 is multicast
			// and must go through mFIB with proper RPF configuration
			err = v.setupIPv6MulticastForHostTap(vrfID, tapSwIfIndex, intf.Spec.SwIfIndex)
			if err != nil {
				return errors.Wrapf(err, "error setting up IPv6 multicast forwarding tap %d in v6 vrf %d", tapSwIfIndex, vrfID)
			}
		}
		for _, addr := range intf.State.Addresses {
			if vpplink.IPFamilyFromIP(addr.IP) == ipFamily {
				err = v.vpp.RouteAdd(&types.Route{
					Table: vrfID,
					Dst:   common.FullyQualified(addr.IP),
					Paths: []types.RoutePath{{
						SwIfIndex: tapSwIfIndex,
					}},
				})
				if err != nil {
					return errors.Wrapf(err, "error add route from VPP to tap0 in VRF %d", vrfID)
				}
				err = v.vpp.AddNeighbor(&types.Neighbor{
					SwIfIndex:    tapSwIfIndex,
					IP:           addr.IP,
					HardwareAddr: intf.State.HardwareAddr,
					Flags:        types.IPNeighborStatic,
				})
				if err != nil {
					return errors.Wrapf(err, "error add static neighbor for tap0 in VRF %d", vrfID)
				}
			}
		}
	}

	err = v.vpp.EnableInterfaceIP6(tapSwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error enabling ip6 for tap %d", tapSwIfIndex)
	}

	// FIXME
	_, cidr, _ := net.ParseCIDR("169.254.0.1/32")
	err = v.vpp.AddInterfaceAddress(tapSwIfIndex, cidr)
	if err != nil {
		return errors.Wrapf(err, "error enabling ip6 for tap %d", tapSwIfIndex)
	}

	// Always set this tap on worker 0
	err = v.vpp.SetInterfaceRxPlacement(tapSwIfIndex, 0 /*queue*/, 0 /*worker*/, false /*main*/)
	if err != nil {
		return errors.Wrap(err, "Error setting tap rx placement")
	}

	err = v.vpp.SetInterfaceMtu(tapSwIfIndex, vpplink.CalicoVppMaxMTu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on tap interface", vpplink.CalicoVppMaxMTu)
	}

	if intf.State.Hasv6 {
		err = v.vpp.DisableIP6RouterAdvertisements(tapSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error disabling ip6 RA on vpptap0")
		}
	}
	err = v.vpp.AddNeighbor(&types.Neighbor{
		SwIfIndex:    tapSwIfIndex,
		IP:           config.VppHostPuntFakeGatewayAddress,
		HardwareAddr: intf.State.HardwareAddr,
		Flags:        types.IPNeighborStatic,
	})
	if err != nil {
		return errors.Wrapf(err, "Error adding neighbor %s to tap", config.VppHostPuntFakeGatewayAddress)
	}
	// In the punt table (where all punted traffics ends), route to the tap
	for _, address := range intf.State.Addresses {
		err = v.vpp.RouteAdd(&types.Route{
			Dst:   address.IPNet,
			Table: common.PuntTableID,
			Paths: []types.RoutePath{{
				Gw:        config.VppHostPuntFakeGatewayAddress,
				SwIfIndex: tapSwIfIndex,
			}},
		})
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		}
	}

	for _, addr := range intf.State.Addresses {
		if addr.IP.To4() == nil {
			log.Infof("Adding ND proxy for address %s", addr.IP)
			err = v.vpp.EnableIP6NdProxy(tapSwIfIndex, addr.IP)
			if err != nil {
				log.Errorf("Error configuring nd proxy for address %s: %v", addr.IP.String(), err)
			}
		}
	}

	if *config.GetCalicoVppDebug().GSOEnabled {
		err = v.vpp.EnableGSOFeature(tapSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on vpptap0")
		}
	}

	err = v.vpp.SetInterfaceRxMode(tapSwIfIndex, types.AllQueues, config.GetCalicoVppInterfaces().VppHostTapSpec.GetRxModeWithDefault(types.AdaptativeRxMode))
	if err != nil {
		log.Errorf("Error SetInterfaceRxMode on vpptap0 %v", err)
	}

	err = v.vpp.CnatEnableFeatures(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error configuring NAT on vpptap0")
	}

	err = v.vpp.RegisterPodInterface(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error configuring vpptap0 as pod intf")
	}

	err = v.vpp.RegisterHostInterface(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error configuring vpptap0 as host intf")
	}

	// Linux side tap setup
	link, err := netlink.LinkByName(intf.Spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", intf.Spec.InterfaceName)
	}

	fakeNextHopIP4, fakeNextHopIP6, err := v.configureLinuxTap(link, *intf.State)
	if err != nil {
		return errors.Wrap(err, "Error configuring tap on linux side")
	}

	err = v.vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	if config.Info.UplinkStatuses != nil {
		config.Info.UplinkStatuses[link.Attrs().Name] = config.UplinkStatus{
			TapSwIfIndex:        tapSwIfIndex,
			SwIfIndex:           intf.Spec.SwIfIndex,
			Mtu:                 uplinkMtu,
			PhysicalNetworkName: intf.Spec.PhysicalNetworkName,
			LinkIndex:           link.Attrs().Index,
			Name:                link.Attrs().Name,
			IsMain:              intf.Spec.IsMain,
			FakeNextHopIP4:      fakeNextHopIP4,
			FakeNextHopIP6:      fakeNextHopIP6,
		}
	}
	return nil
}

func (v *VppRunner) doVppGlobalConfiguration() (err error) {
	// Create all VRFs with a static ID that we use first so that we can
	// then call AllocateVRF without risk of conflict
	for _, ipFamily := range vpplink.IPFamilies {
		err := v.vpp.AddVRF(common.PuntTableID, ipFamily.IsIP6, fmt.Sprintf("punt-table-%s", ipFamily.Str))
		if err != nil {
			return errors.Wrapf(err, "Error creating punt vrf %s", ipFamily.Str)
		}
		err = v.vpp.AddVRF(common.PodVRFIndex, ipFamily.IsIP6, fmt.Sprintf("calico-pods-%s", ipFamily.Str))
		if err != nil {
			return err
		}
		err = v.vpp.AddDefaultRouteViaTable(common.PodVRFIndex, common.DefaultVRFIndex, ipFamily.IsIP6)
		if err != nil {
			return err
		}
	}

	err = v.vpp.SetK8sSnatPolicy()
	if err != nil {
		return errors.Wrap(err, "Error configuring cnat source policy")
	}

	err = v.vpp.ConfigureNeighborsV4(&types.NeighborConfig{
		MaxNumber: *config.GetCalicoVppInitialConfig().IP4NeighborsMaxNumber,
		MaxAge:    *config.GetCalicoVppInitialConfig().IP4NeighborsMaxAge,
	})
	if err != nil {
		return errors.Wrap(err, "error configuring v4 ip neighbors")
	}

	err = v.vpp.ConfigureNeighborsV6(&types.NeighborConfig{
		MaxNumber: *config.GetCalicoVppInitialConfig().IP6NeighborsMaxNumber,
		MaxAge:    *config.GetCalicoVppInitialConfig().IP6NeighborsMaxAge,
	})
	if err != nil {
		return errors.Wrap(err, "error configuring v6 ip neighbors")
	}

	for _, ipFamily := range vpplink.IPFamilies {
		err = v.vpp.PuntRedirect(types.IPPuntRedirect{
			RxSwIfIndex: vpplink.InvalidID,
			Paths: []types.RoutePath{{
				Table:     common.PuntTableID,
				SwIfIndex: types.InvalidID,
			}},
		}, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring punt redirect")
		}

		err = v.vpp.PuntAllL4(ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring L4 punt")
		}
	}
	return nil
}

func (v *VppRunner) updateCalicoNode(ifState *config.LinuxInterfaceState) (err error) {
	var node, updated *oldv3.Node
	var client calicov3cli.Interface
	// TODO create if doesn't exist? need to be careful to do it atomically... and everyone else must as well.
	for i := 0; i < 100; i++ {
		client, err = calicov3cli.NewFromEnv()
		if err != nil {
			return errors.Wrap(err, "Error creating calico client")
		}
		ctx, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel1()
		node, err = client.Nodes().Get(ctx, *config.NodeName, calicoopts.GetOptions{})
		if err != nil {
			log.Warnf("Try [%d/10] cannot get current node from Calico %+v", i, err)
			time.Sleep(1 * time.Second)
			continue
		}
		// Update node with address
		needUpdate := false
		if node.Spec.BGP == nil {
			node.Spec.BGP = &oldv3.NodeBGPSpec{}
		}
		if ifState.Hasv4 {
			log.Infof("Setting BGP nodeIP %s", ifState.NodeIP4)
			if node.Spec.BGP.IPv4Address != ifState.NodeIP4 {
				node.Spec.BGP.IPv4Address = ifState.NodeIP4
				needUpdate = true
			}
		} else {
			node.Spec.BGP.IPv4Address = ""
			needUpdate = true
		}
		if ifState.Hasv6 {
			log.Infof("Setting BGP nodeIP %s", ifState.NodeIP6)
			if node.Spec.BGP.IPv6Address != ifState.NodeIP6 {
				node.Spec.BGP.IPv6Address = ifState.NodeIP6
				needUpdate = true
			}
		} else {
			node.Spec.BGP.IPv6Address = ""
			needUpdate = true
		}
		if needUpdate {
			log.Infof("Updating node, version = %s, metaversion = %s", node.ResourceVersion, node.ResourceVersion)
			log.Debugf("updating node with: %+v", node)
			ctx, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel2()
			updated, err = client.Nodes().Update(ctx, node, calicoopts.SetOptions{})
			if err != nil {
				log.Warnf("Try [%d/10] cannot update current node: %+v", i, err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debugf("Updated node: %+v", updated)
			return nil
		} else {
			log.Infof("Node doesn't need updating :)")
			return nil
		}
	}
	return errors.Wrap(err, "Error updating node")
}

// allocatePhysicalNetworkVRFs allocates two VRFs for a phyiscal network
// and adds a route from the podVRF to the main VRF
func (v *VppRunner) allocatePhysicalNetworkVRFs(physicalNetworkName string) (*config.PhysicalNetwork, error) {
	mainVrfID, err := v.vpp.AllocateVRF(false, fmt.Sprintf("physical-net-%s-ip4", physicalNetworkName))
	if err != nil {
		return nil, errors.Wrapf(err, "error allocating VRF physical-net-%s-ip4", physicalNetworkName)
	}
	podVrfID, err := v.vpp.AllocateVRF(false, fmt.Sprintf("calico-pods-%s-ip4", physicalNetworkName))
	if err != nil {
		return nil, errors.Wrapf(err, "error allocating VRF calico-pods-%s-ip4", physicalNetworkName)
	}
	err = v.vpp.AddVRF(mainVrfID, true, fmt.Sprintf("physical-net-%s-ip6", physicalNetworkName))
	if err != nil {
		return nil, errors.Wrapf(err, "error allocating VRF physical-net-%s-ip6", physicalNetworkName)
	}
	err = v.vpp.AddVRF(podVrfID, true, fmt.Sprintf("calico-pods-%s-ip6", physicalNetworkName))
	if err != nil {
		return nil, errors.Wrapf(err, "error allocating VRF calico-pods-%s-ip6", physicalNetworkName)
	}
	for _, ipFamily := range vpplink.IPFamilies {
		err = v.vpp.AddDefaultRouteViaTable(podVrfID, mainVrfID, ipFamily.IsIP6)
		if err != nil {
			return nil, errors.Wrapf(err, "error adding default %s route from podVRF to mainVRF for physical network %s", ipFamily.Str, physicalNetworkName)
		}
	}
	return &config.PhysicalNetwork{
		VrfID:    mainVrfID,
		PodVrfID: podVrfID,
	}, nil
}

// Returns VPP exit code
func (v *VppRunner) runVpp() (err error) {
	if !v.params.AllInterfacesPhysical() { // use separate net namespace because linux deletes these interfaces when ns is deleted
		if ns.IsNSorErr(utils.GetnetnsPath(config.VppNetnsName)) != nil {
			_, err = utils.NewNS(config.VppNetnsName)
			if err != nil {
				return errors.Wrap(err, "Could not add VPP netns")
			}
		}

		/**
		 * Run VPP in an isolated network namespace, used to park the interface
		 * in af_packet or af_xdp mode */
		err = ns.WithNetNSPath(utils.GetnetnsPath(config.VppNetnsName), func(ns.NetNS) (err error) {
			vppCmd := exec.Command(config.VppPath, "-c", config.VppConfigFile)
			vppCmd.Stdout = os.Stdout
			vppCmd.Stderr = os.Stderr
			err = vppCmd.Start()
			if err != nil {
				return err
			}
			vppProcess = vppCmd.Process
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "Error starting vpp process")
		}
	} else { // use vpp own net namespace
		// From this point it is very important that every exit path calls restoreConfiguration after vpp exits
		vppCmd := exec.Command(config.VppPath, "-c", config.VppConfigFile)
		vppCmd.SysProcAttr = &syscall.SysProcAttr{
			// Run VPP in an isolated network namespace, used to park the interface in
			// af_packet or af_xdp mode
			Cloneflags: syscall.CLONE_NEWNET,
		}
		vppCmd.Stdout = os.Stdout
		vppCmd.Stderr = os.Stderr
		err = vppCmd.Start()

		if err != nil {
			return errors.Wrap(err, "Error starting vpp process")
		}
		vppProcess = vppCmd.Process
	}

	// From this point it is very important that every exit
	// path calls restoreConfiguration after vpp exits
	defer v.restoreConfiguration()

	log.Infof("VPP started [PID %d]", vppProcess.Pid)
	runningCond.Broadcast()

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(config.GetCalicoVppInitialConfig().VppStartupSleepSeconds) * time.Second)

	vpp, err := utils.CreateVppLink()
	v.vpp = vpp
	if err != nil {
		terminateVpp("Error connecting to VPP: %v", err)
		<-vppDeadChan
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}

	err = v.doVppGlobalConfiguration()
	if err != nil {
		terminateVpp("Error configuring VPP: %v", err)
		v.vpp.Close()
		<-vppDeadChan
		return errors.Wrap(err, "Error configuring VPP")
	}

	// add main network that has the default VRF
	config.Info.PhysicalNets[config.DefaultPhysicalNetworkName] = config.PhysicalNetwork{VrfID: common.DefaultVRFIndex, PodVrfID: common.PodVRFIndex}

	for interfaceName, intf := range v.params.Interfaces {
		err = v.configureVppUplinkInterface(intf)
		if err != nil {
			terminateVpp("Error configuring VPP interface %s %v", interfaceName, err)
			<-vppDeadChan
			return errors.Wrapf(err, "Error configuring VPP interface %s", interfaceName)
		}
	}
	// Update the Calico node with the IP address actually configured on VPP
	err = v.updateCalicoNode(v.params.InterfacesById[0].State)
	if err != nil {
		terminateVpp("Error updating Calico node (SIGINT %d): %v", vppProcess.Pid, err)
		<-vppDeadChan
		return errors.Wrap(err, "Error updating Calico node: please check inter-node connectivity and service prefix")
	}

	config.Info.Status = config.Ready
	err = utils.WriteInfoFile()
	if err != nil {
		log.Errorf("Error writing vpp manager file: %v", err)
	}

	// close vpp as we do not program
	v.vpp.Close()

	networkHook.ExecuteWithUserScript(hooks.HookVppRunning, config.HookScriptVppRunning)

	<-vppDeadChan
	log.Infof("VPP Exited: status %v", err)

	return nil
}

func (v *VppRunner) restoreConfiguration() {
	log.Infof("Restoring configuration")
	err := utils.ClearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing vpp manager files: %v", err)
	}
	for _, intf := range v.params.Interfaces {
		intf.Driver.RestoreLinux()
	}
	err = utils.PingCalicoVpp()
	if err != nil {
		log.Errorf("Error pinging calico-vpp: %v", err)
	}
}
