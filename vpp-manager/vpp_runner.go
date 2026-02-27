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
	"strconv"
	"strings"
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
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/uplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type VppRunner struct {
	params       *config.VppManagerParams
	conf         []*config.LinuxInterfaceState
	vpp          *vpplink.VppLink
	uplinkDriver []uplink.UplinkDriver
}

// getUplinkAddressWithMask will update the mask of an ipv6 address
// and set it from /128 to /64 if the option 'TranslateUplinkAddrMaskTo64' is set
// this will not update Link-local addresses
func getUplinkAddressWithMask(addr *net.IPNet) *net.IPNet {
	if addr == nil || addr.IP == nil || addr.IP.To4() != nil || addr.IP.IsLinkLocalUnicast() {
		return addr
	}
	if !*config.GetCalicoVppDebug().TranslateUplinkAddrMaskTo64 {
		return addr
	}
	ones, _ := addr.Mask.Size()
	if ones != 128 {
		return addr
	}
	return &net.IPNet{
		IP:   addr.IP,
		Mask: net.CIDRMask(64, 128),
	}
}

func NewVPPRunner(params *config.VppManagerParams, confs []*config.LinuxInterfaceState) *VppRunner {
	return &VppRunner{
		params: params,
		conf:   confs,
	}
}

func (v *VppRunner) GenerateVppConfigExecFile() error {
	template, err := config.TemplateScriptReplace(*config.ConfigExecTemplate, v.params, v.conf)
	if err != nil {
		return err
	}
	err = errors.Wrapf(
		os.WriteFile(config.VppConfigExecFile, []byte(template+"\n"), 0744),
		"Error writing VPP Exec configuration to %s",
		config.VppConfigExecFile,
	)
	return err
}

func (v *VppRunner) GenerateVppConfigFile(drivers []uplink.UplinkDriver) error {
	template, err := config.TemplateScriptReplace(*config.ConfigTemplate, v.params, v.conf)
	if err != nil {
		return err
	}
	for _, driver := range drivers {
		template = driver.UpdateVppConfigFile(template)
	}
	err = errors.Wrapf(
		os.WriteFile(config.VppConfigFile, []byte(template+"\n"), 0644),
		"Error writing VPP configuration to %s",
		config.VppConfigFile,
	)
	return err
}

func (v *VppRunner) Run(drivers []uplink.UplinkDriver) error {
	v.uplinkDriver = drivers
	for idx := range v.conf {
		log.Infof("Running with uplink %s", drivers[idx].GetName())
	}
	err := v.GenerateVppConfigExecFile()
	if err != nil {
		return errors.Wrap(err, "Error generating VPP config Exec")
	}

	err = v.GenerateVppConfigFile(drivers)
	if err != nil {
		return errors.Wrap(err, "Error generating VPP config")
	}

	for idx := range v.conf {
		err = v.uplinkDriver[idx].PreconfigureLinux()
		if err != nil {
			return errors.Wrapf(err, "Error pre-configuring Linux main IF: %s", v.uplinkDriver[idx])
		}
	}

	networkHook.ExecuteWithUserScript(hooks.HookBeforeVppRun, config.HookScriptBeforeVppRun, v.params)

	err = v.runVpp()
	if err != nil {
		return errors.Wrapf(err, "Error running VPP")
	}

	networkHook.ExecuteWithUserScript(hooks.HookVppDoneOk, config.HookScriptVppDoneOk, v.params)
	return nil
}

func (v *VppRunner) configureGlobalPunt() (err error) {
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
	return
}

// configurePunt adds in VPP in the punt table routes to the tap.
// traffic 'for me' received on the PHY and on the pods in this node
// will end up here.
func (v *VppRunner) configurePunt(tapSwIfIndex uint32, ifState config.LinuxInterfaceState) (err error) {
	for _, addr := range ifState.GetAddresses() {
		err = v.vpp.RouteAdd(&types.Route{
			Table: common.PuntTableID,
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
	if ifState.IPv6LinkLocal.IPNet != nil {
		err = v.vpp.RouteAdd(&types.Route{
			Table: common.PuntTableID,
			Dst:   common.FullyQualified(ifState.IPv6LinkLocal.IP),
			Paths: []types.RoutePath{{
				Gw:        ifState.IPv6LinkLocal.IP,
				SwIfIndex: tapSwIfIndex,
			}},
		})
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		}
	}
	return nil
}

// pick a next hop to use for cluster routes (services, pod cidrs) in the address prefix
func (v *VppRunner) pickNextHopIP(ifState config.LinuxInterfaceState) (fakeNextHopIP4, fakeNextHopIP6 net.IP) {
	fakeNextHopIP4 = net.ParseIP("0.0.0.0")
	fakeNextHopIP6 = net.ParseIP("::")
	var nhAddr net.IP
	foundV4, foundV6 := false, false
	needsV4, needsV6 := false, false

	for _, addr := range ifState.GetAddresses() {
		if addr.IP.To4() != nil {
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
		} else if !foundV6 {
			log.Infof("Using %s as next hop for cluster IPv6 routes", nhAddr.String())
			fakeNextHopIP6 = nhAddr
			foundV6 = true
		}
	}

	if !((needsV4 && !foundV4) || (needsV6 && !foundV6)) { //nolint:staticcheck
		return
	}

	for _, route := range ifState.GetRoutes() {
		if route.Gw != nil || route.Dst == nil {
			// We're looking for a directly connected route
			continue
		}
		if (route.Dst.IP.To4() != nil && foundV4) || (route.Dst.IP.To4() == nil && foundV6) {
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
				if ifState.HasAddr(nhAddr) {
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
				if ifState.HasAddr(nhAddr) {
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

	if ifState.HasNodeIP6() {
		err := podinterface.WriteProcSys("/proc/sys/net/ipv6/conf/"+link.Attrs().Name+"/disable_ipv6", "0")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to set net.ipv6.conf."+link.Attrs().Name+".disable_ipv6=0: %s", err)
		}
	}
	// Configure original addresses and routes on the new tap
	for _, addr := range ifState.GetAddresses() {
		log.Infof("Adding address %+v to tap interface", addr)
		err = netlink.AddrAdd(link, &addr)
		if err == syscall.EEXIST {
			log.Warnf("add addr %+v via vpp EEXIST, %+v", addr, err)
		} else if err != nil {
			log.Errorf("Error adding address %s to tap interface: %v", addr, err)
		}
	}
	for _, route := range ifState.GetRoutes() {
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

func (v *VppRunner) allocateStaticVRFs() error {
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
	return nil
}

// setupIPv6MulticastForHostTap configures mFIB entries to allow IPv6 multicast traffic
// from the Linux host to pass through VPP. This is required for DHCPv6, NDP, and other
// IPv6 protocols that use link-local multicast.
// Without this configuration, packets arriving from the tap interface fail RPF checks
// because the tap interface is not in the mFIB accept list.
func (v *VppRunner) setupIPv6MulticastForHostTap(vrfID uint32, tapSwIfIndex uint32, uplinkSwIfIndex uint32) error {
	log.Infof("Setting up IPv6 multicast forwarding for host tap in VRF %d", vrfID)

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
			log.Warnf("Invalid multicast address: %s", group.addr)
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

		log.Infof("Added mFIB route for %s (%s) in VRF %d", group.addr, group.comment, vrfID)
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
				log.Errorf("cannot add broadcast route in vpp: %v", err)
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
		err = v.vpp.AddDefaultRouteViaTable(vrfID, config.Info.PhysicalNets[ifSpec.PhysicalNetworkName].VrfID, ipFamily.IsIP6)
		if err != nil {
			return []uint32{}, errors.Wrapf(err, "error adding VRF %d default route via VRF %d", vrfID, config.Info.PhysicalNets[ifSpec.PhysicalNetworkName])
		}
		// Set tap in this table
		err = v.vpp.SetInterfaceVRF(tapSwIfIndex, vrfID, ipFamily.IsIP6)
		if err != nil {
			return []uint32{}, errors.Wrapf(err, "error setting vpp tap in vrf %d", vrfID)
		}
		vrfs = append(vrfs, vrfID)

		for _, addr := range ifState.GetAddresses() {
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

// configureVppUplinkInterface configures one uplink interface in VPP
// and creates the corresponding tap in Linux
func (v *VppRunner) configureVppUplinkInterface(
	uplinkDriver uplink.UplinkDriver,
	ifState *config.LinuxInterfaceState,
	ifSpec config.UplinkInterfaceSpec,
) (err error) {
	// Configure the physical network if we see it for the first time
	if _, ok := config.Info.PhysicalNets[ifSpec.PhysicalNetworkName]; !ok {
		err = v.AllocatePhysicalNetworkVRFs(ifSpec.PhysicalNetworkName)
		if err != nil {
			return err
		}
	}

	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	if *config.GetCalicoVppDebug().GSOEnabled {
		err = v.vpp.EnableGSOFeature(ifSpec.SwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on uplink interface")
		}
	}

	uplinkMtu := vpplink.DefaultIntTo(ifSpec.Mtu, ifState.Mtu)
	err = v.vpp.SetInterfaceMtu(ifSpec.SwIfIndex, uplinkMtu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on uplink interface", uplinkMtu)
	}

	err = v.vpp.SetInterfaceRxMode(ifSpec.SwIfIndex, types.AllQueues, ifSpec.GetRxModeWithDefault(uplinkDriver.GetDefaultRxMode()))
	if err != nil {
		log.Warnf("%v", err)
	}

	err = v.vpp.EnableInterfaceIP6(ifSpec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling ipv6 on uplink interface")
	}

	err = v.vpp.DisableIP6RouterAdvertisements(ifSpec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error disabling ipv6 RA on uplink interface")
	}

	err = v.vpp.CnatEnableFeatures(ifSpec.SwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error configuring NAT on uplink interface")
	}

	if ifSpec.PhysicalNetworkName != "" {
		for _, ipFamily := range vpplink.IPFamilies {
			err = v.vpp.SetInterfaceVRF(ifSpec.SwIfIndex, config.Info.PhysicalNets[ifSpec.PhysicalNetworkName].VrfID, ipFamily.IsIP6)
			if err != nil {
				return errors.Wrapf(err, "error setting interface in vrf %d", config.Info.PhysicalNets[ifSpec.PhysicalNetworkName])
			}
		}
		value := config.Info.PhysicalNets[ifSpec.PhysicalNetworkName]
		config.Info.PhysicalNets[ifSpec.PhysicalNetworkName] = config.PhysicalNetwork{
			VrfID:    value.VrfID,
			PodVrfID: value.PodVrfID,
		}
	}

	for _, addr := range ifState.GetAddresses() {
		log.Infof("Adding address %s to uplink interface", getUplinkAddressWithMask(addr.IPNet).String())
		err = v.vpp.AddInterfaceAddress(ifSpec.SwIfIndex, getUplinkAddressWithMask(addr.IPNet))
		if err != nil {
			return errors.Wrapf(err, "Error adding address %s to uplink interface", getUplinkAddressWithMask(addr.IPNet))
		}
	}
	for _, route := range ifState.GetRoutes() {
		err = v.vpp.RouteAdd(&types.Route{
			Dst: route.Dst,
			Paths: []types.RoutePath{{
				Gw:        route.Gw,
				SwIfIndex: ifSpec.SwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("cannot add route in vpp: %v", err)
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
				SwIfIndex: ifSpec.SwIfIndex,
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
			HostInterfaceName: ifSpec.InterfaceName,
			RxQueueSize:       config.GetCalicoVppInterfaces().VppHostTapSpec.RxQueueSize,
			TxQueueSize:       config.GetCalicoVppInterfaces().VppHostTapSpec.TxQueueSize,
			HardwareAddr:      ifSpec.GetVppSideHardwareAddress(),
		},
		HostNamespace:  "pid:1", // create tap in root netns
		Tag:            "host-" + ifSpec.InterfaceName,
		Flags:          vpptap0Flags,
		HostMtu:        uplinkMtu,
		HostMacAddress: ifState.HardwareAddr,
	})
	if err != nil {
		return errors.Wrap(err, "Error creating tap")
	}

	ifState.TapSwIfIndex = tapSwIfIndex

	if ifState.HasNodeIP6() {
		// wait 5s for the interface creation in linux and fetch its LL address
	doublebreak:
		for i := uint32(0); i <= *config.GetCalicoVppDebug().FetchV6LLntries; i++ {
			time.Sleep(time.Second)
			link, err := netlink.LinkByName(ifSpec.InterfaceName)
			if err != nil {
				log.WithError(err).Warnf("cannot find interface %s", ifSpec.InterfaceName)
				continue
			}
			addresses, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err != nil {
				log.WithError(err).Warnf("could not find v6 address on link %s", ifSpec.InterfaceName)
				continue
			}
			for _, addr := range addresses { // addresses are only v6 here see above
				if addr.IP.IsLinkLocalUnicast() {
					log.Infof("Using link-local addr %s for %s", common.FullyQualified(addr.IP), ifSpec.InterfaceName)
					ifState.IPv6LinkLocal = addr
					break doublebreak
				}
			}
			if i == *config.GetCalicoVppDebug().FetchV6LLntries-1 {
				log.Warnf("Could not find v6 LL address for %s after %ds", ifSpec.InterfaceName, *config.GetCalicoVppDebug().FetchV6LLntries)
			}
		}
	}

	vrfs, err := v.setupTapVRF(&ifSpec, ifState, tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error configuring VRF for tap")
	}

	// Always set this tap on worker 0
	err = v.vpp.SetInterfaceRxPlacement(tapSwIfIndex, 0 /*queue*/, 0 /*worker*/, false /*main*/)
	if err != nil {
		return errors.Wrap(err, "Error setting tap rx placement")
	}

	err = v.vpp.SetPromiscOn(tapSwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error setting vpptap0 promisc")
	}

	err = v.vpp.SetInterfaceMtu(uint32(tapSwIfIndex), vpplink.CalicoVppMaxMTu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on tap interface", vpplink.CalicoVppMaxMTu)
	}

	if ifState.HasNodeIP6() {
		err = v.vpp.DisableIP6RouterAdvertisements(tapSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error disabling ip6 RA on vpptap0")
		}
	}
	err = v.configurePunt(tapSwIfIndex, *ifState)
	if err != nil {
		return errors.Wrap(err, "Error adding redirect to tap")
	}
	err = v.vpp.EnableArpProxy(tapSwIfIndex, vrfs[0 /* ip4 */])
	if err != nil {
		return errors.Wrap(err, "Error enabling ARP proxy")
	}

	for _, addr := range ifState.GetAddresses() {
		if addr.IP.To4() == nil {
			log.Infof("Adding ND proxy for address %s", addr.IP)
			err = v.vpp.EnableIP6NdProxy(tapSwIfIndex, addr.IP)
			if err != nil {
				log.Errorf("Error configuring nd proxy for address %s: %v", addr.IP.String(), err)
			}
		}
	}

	if ifState.IPv6LinkLocal.IPNet != nil {
		err = v.vpp.AddInterfaceAddress(ifSpec.SwIfIndex, common.FullyQualified(ifState.IPv6LinkLocal.IP))
		if err != nil {
			return errors.Wrapf(err, "Error adding address %s to uplink interface: %d", common.FullyQualified(ifState.IPv6LinkLocal.IP), ifSpec.SwIfIndex)
		}
		err = v.vpp.EnableIP6NdProxy(tapSwIfIndex, ifState.IPv6LinkLocal.IP)
		if err != nil {
			return errors.Wrapf(err, "Error configuring nd proxy for address %s", ifState.IPv6LinkLocal.IP.String())
		}
	}

	/*
	 * Add ND proxy for IPv6 gateway addresses.
	 * Without ND proxy for gateway, host's NS for gateway is dropped with "neighbor
	 * solicitations for unknown targets" error because there's no /128 FIB entry.
	 * This requires VPP patch https://gerrit.fd.io/r/c/vpp/+/44350 to fix NA loop bug.
	 */
	for _, route := range ifState.GetRoutes() {
		if route.Gw != nil && route.Gw.To4() == nil {
			log.Infof("Adding ND proxy for IPv6 gateway %s", route.Gw)
			err = v.vpp.EnableIP6NdProxy(tapSwIfIndex, route.Gw)
			if err != nil {
				log.Errorf("Error configuring ND proxy for gateway %s: %v", route.Gw, err)
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

	// Get Linux link info for the tap but do NOT bring it up yet.
	// Linux tap configuration (link up, addresses, routes) is deferred
	// to after the VPP_RUNNING hook so that udev rules restoring
	// ID_NET_NAME_* properties are in place before systemd-networkd
	// sees the interface and computes the DHCPv6 IAID.
	link, err := netlink.LinkByName(ifSpec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", ifSpec.InterfaceName)
	}

	fakeNextHopIP4, fakeNextHopIP6 := v.pickNextHopIP(*ifState)

	config.Info.UplinkStatuses[link.Attrs().Name] = config.UplinkStatus{
		TapSwIfIndex:        tapSwIfIndex,
		SwIfIndex:           ifSpec.SwIfIndex,
		Mtu:                 uplinkMtu,
		PhysicalNetworkName: ifSpec.PhysicalNetworkName,
		LinkIndex:           link.Attrs().Index,
		Name:                link.Attrs().Name,
		IsMain:              ifSpec.IsMain,
		FakeNextHopIP4:      fakeNextHopIP4,
		FakeNextHopIP6:      fakeNextHopIP6,
		UplinkAddresses:     ifState.GetAddressesAsIPNet(),
	}
	return nil
}

func (v *VppRunner) doVppGlobalConfiguration() (err error) {
	err = v.allocateStaticVRFs()
	if err != nil {
		return errors.Wrap(err, "Error creating static VRFs in VPP")
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

	return nil
}

func (v *VppRunner) updateCalicoNode(ifState *config.LinuxInterfaceState) (err error) {
	var node, updated *oldv3.Node
	var client calicov3cli.Interface
	// TODO create if doesn't exist? need to be careful to do it atomically... and everyone else must as well.
	for i := 0; i < 10; i++ {
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
		if ifState.HasNodeIP4() {
			log.Infof("Setting BGP nodeIP %s", ifState.GetNodeIP4())
			if node.Spec.BGP.IPv4Address != ifState.GetNodeIP4() {
				node.Spec.BGP.IPv4Address = ifState.GetNodeIP4()
				needUpdate = true
			}
		} else {
			node.Spec.BGP.IPv4Address = ""
			needUpdate = true
		}
		if ifState.HasNodeIP6() {
			log.Infof("Setting BGP nodeIP %s", ifState.GetNodeIP6())
			if node.Spec.BGP.IPv6Address != ifState.GetNodeIP6() {
				node.Spec.BGP.IPv6Address = ifState.GetNodeIP6()
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

func (v *VppRunner) pingCalicoVpp() error {
	dat, err := os.ReadFile(config.CalicoVppPidFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Infof("calico-vpp-pid file doesn't exist. Agent probably not started")
			return nil
		}
		return errors.Wrapf(err, "Error reading %s", config.CalicoVppPidFile)
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 32)
	if err != nil {
		return errors.Wrapf(err, "Error parsing %s", dat)
	}
	err = syscall.Kill(int(pid), syscall.SIGUSR1)
	if err != nil {
		return errors.Wrapf(err, "Error kill -SIGUSR1 %d", int(pid))
	}
	log.Infof("Did kill -SIGUSR1 %d", int(pid))
	return nil
}

func (v *VppRunner) allInterfacesPhysical() bool {
	for _, ifConf := range v.conf {
		if ifConf.IsTunTap || ifConf.IsVeth {
			return false
		}
	}
	return true
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
	config.Info.PhysicalNets[phyNet] = config.PhysicalNetwork{VrfID: mainVrfID, PodVrfID: podVrfID}
	return nil
}

func (v *VppRunner) configureDHCPv6HopLimit() {
	log.Infof("Configuring ip6tables mangle OUTPUT rule for DHCPv6 hop limit on host")

	checkCmd := exec.Command("/usr/sbin/ip6tables", "-t", "mangle", "-C", "OUTPUT",
		"-p", "udp", "--sport", "546", "--dport", "547",
		"-j", "HL", "--hl-set", "2")
	if err := checkCmd.Run(); err != nil {
		outputCmd := exec.Command("/usr/sbin/ip6tables", "-t", "mangle", "-A", "OUTPUT",
			"-p", "udp", "--sport", "546", "--dport", "547",
			"-j", "HL", "--hl-set", "2")
		outputCmd.Stdout = os.Stdout
		outputCmd.Stderr = os.Stderr
		if err := outputCmd.Run(); err != nil {
			log.Warnf("Failed to configure ip6tables mangle OUTPUT rule for DHCPv6: %v", err)
		}
	} else {
		log.Infof("ip6tables mangle OUTPUT rule for DHCPv6 already present")
	}
}

func (v *VppRunner) cleanupDHCPv6HopLimit() {
	log.Infof("Cleaning up ip6tables mangle OUTPUT rule for DHCPv6 hop limit on host")

	checkCmd := exec.Command("/usr/sbin/ip6tables", "-t", "mangle", "-C", "OUTPUT",
		"-p", "udp", "--sport", "546", "--dport", "547",
		"-j", "HL", "--hl-set", "2")
	if err := checkCmd.Run(); err == nil {
		deleteCmd := exec.Command("/usr/sbin/ip6tables", "-t", "mangle", "-D", "OUTPUT",
			"-p", "udp", "--sport", "546", "--dport", "547",
			"-j", "HL", "--hl-set", "2")
		deleteCmd.Stdout = os.Stdout
		deleteCmd.Stderr = os.Stderr
		if err := deleteCmd.Run(); err != nil {
			log.Warnf("Failed to delete ip6tables mangle OUTPUT rule for DHCPv6: %v", err)
		}
	} else {
		log.Infof("ip6tables mangle OUTPUT rule for DHCPv6 not present")
	}
}

// Returns VPP exit code
func (v *VppRunner) runVpp() (err error) {
	if !v.allInterfacesPhysical() { // use separate net namespace because linux deletes these interfaces when ns is deleted
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

	defer func() {
		if r := recover(); r != nil {
			// we recover and log the error if there is a bug in vpp-manager
			fmt.Println("Recovered. Error:\n", r)
			// then we kill vpp and restore configuration
			terminateVpp("Killing VPP, error in vpp-manager : %v", r)
			// we need to wait a bit to make sure VPP is dead before restoring config
			time.Sleep(time.Second * 5)
			v.restoreConfiguration(v.allInterfacesPhysical())
		} else {
			/**
			 * From this point it is very important that every exit
			 * path calls restoreConfiguration if vpp exits
			 * this is called when vppDeadChan is triggered */
			v.restoreConfiguration(v.allInterfacesPhysical())
		}
	}()

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

	// FIXME This is a temporary workaround using ip6tables to set the hop limit for DHCPv6.
	// Ideally, VPP should have a dedicated node for handling this.
	// Without this, when forwarding a DHCPv6 SOLICIT/REQUEST packet, VPP will decrement the
	// hop-limit by 1. Since client generates DHCPv6 SOLICIT/REQUEST with hop-limit=1, VPP
	// drops it (ip6 ttl <= 1) with ICMP time exceeded and DHCPv6 lease negotiation fails.
	v.configureDHCPv6HopLimit()

	// add main network that has the default VRF
	config.Info.PhysicalNets[config.DefaultPhysicalNetworkName] = config.PhysicalNetwork{VrfID: common.DefaultVRFIndex, PodVrfID: common.PodVRFIndex}

	err = v.configureGlobalPunt()
	if err != nil {
		return errors.Wrap(err, "Error adding redirect to tap")
	}
	for idx := 0; idx < len(v.params.UplinksSpecs); idx++ {
		err := v.uplinkDriver[idx].CreateMainVppInterface(vpp, vppProcess.Pid, &v.params.UplinksSpecs[idx])
		if err != nil {
			terminateVpp("Error creating uplink interface %s: %v", v.params.UplinksSpecs[idx].InterfaceName, err)
			v.vpp.Close()
			<-vppDeadChan
			return errors.Wrap(err, "Error creating uplink interface")
		}

		// Data interface configuration
		err = v.vpp.Retry(2*time.Second, 10, v.vpp.InterfaceAdminUp, v.params.UplinksSpecs[idx].SwIfIndex)
		if err != nil {
			terminateVpp("Error setting uplink interface up: %v", err)
			v.vpp.Close()
			<-vppDeadChan
			return errors.Wrap(err, "Error setting uplink interface up")
		}

		err = v.configureVppUplinkInterface(v.uplinkDriver[idx], v.conf[idx], v.params.UplinksSpecs[idx])

		if err != nil {
			terminateVpp("Error configuring VPP: %v", err)
			<-vppDeadChan
			return errors.Wrap(err, "Error configuring VPP")
		}
	}

	networkHook.ExecuteWithUserScript(hooks.HookVppRunning, config.HookScriptVppRunning, v.params)

	// Configure Linux side of tap interfaces AFTER the VPP_RUNNING hook.
	// The hook installs udev rules that restore ID_NET_NAME_* properties
	// on the tap, which systemd-networkd uses to compute a stable DHCPv6
	// IAID. Bringing the taps up only now guarantees the udev rules are
	// loaded and networkd has been restarted before any DHCPv6 SOLICIT
	// can be sent, preventing IAID mismatch.
	for idx := 0; idx < len(v.params.UplinksSpecs); idx++ {
		link, err := netlink.LinkByName(v.params.UplinksSpecs[idx].InterfaceName)
		if err != nil {
			terminateVpp("Error finding tap interface %s: %v", v.params.UplinksSpecs[idx].InterfaceName, err)
			<-vppDeadChan
			return errors.Wrapf(err, "Error finding tap interface %s", v.params.UplinksSpecs[idx].InterfaceName)
		}
		_, _, err = v.configureLinuxTap(link, *v.conf[idx])
		if err != nil {
			terminateVpp("Error configuring Linux tap: %v", err)
			<-vppDeadChan
			return errors.Wrap(err, "Error configuring tap on linux side")
		}
	}

	// Set the TAP interfaces admin-up in VPP last, after all Linux-side
	// configuration is complete.
	for idx := 0; idx < len(v.params.UplinksSpecs); idx++ {
		err = v.vpp.InterfaceAdminUp(v.conf[idx].TapSwIfIndex)
		if err != nil {
			terminateVpp("Error setting VPP uplink tap %d up, %v", v.conf[idx].TapSwIfIndex, err)
			<-vppDeadChan
			return errors.Wrapf(err, "Error setting VPP uplink tap %d up", v.conf[idx].TapSwIfIndex)
		}
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = v.updateCalicoNode(v.conf[0])
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

	// close the vpp API chan as beyond this point VPP-manager will not interact with VPP anymore
	v.vpp.Close()
	<-vppDeadChan
	log.Infof("VPP Exited: status %v", err)

	return nil
}

func (v *VppRunner) restoreConfiguration(allInterfacesPhysical bool) {
	log.Infof("Restoring configuration")
	v.cleanupDHCPv6HopLimit()
	err := utils.ClearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing vpp manager files: %v", err)
	}
	for idx := range v.params.UplinksSpecs {
		v.uplinkDriver[idx].RestoreLinux(allInterfacesPhysical)
	}
	err = v.pingCalicoVpp()
	if err != nil {
		log.Errorf("Error pinging calico-vpp: %v", err)
	}
}
