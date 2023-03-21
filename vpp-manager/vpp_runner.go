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
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/pod_interface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/uplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

var (
	fakeNextHopIP4    = net.ParseIP("0.0.0.0")
	fakeNextHopIP6    = net.ParseIP("::")
	fakeVppNextHopIP4 = net.ParseIP("169.254.0.1")
	fakeVppNextHopIP6 = net.ParseIP("fc00:ffff:ffff:ffff:ca11:c000:fd10:fffe")
	vppSideMac, _     = net.ParseMAC("02:ca:11:c0:fd:10")
)

type VppRunner struct {
	params       *config.VppManagerParams
	conf         []*config.LinuxInterfaceState
	vpp          *vpplink.VppLink
	uplinkDriver []uplink.UplinkDriver
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

	hooks.RunHook(hooks.BEFORE_VPP_RUN, v.params, v.conf)
	err = v.runVpp()
	if err != nil {
		return errors.Wrapf(err, "Error running VPP")
	}
	hooks.RunHook(hooks.VPP_DONE_OK, v.params, v.conf)
	return nil
}

func (v *VppRunner) configurePunt(tapSwIfIndex uint32, ifState config.LinuxInterfaceState) (err error) {
	for _, ipFamily := range vpplink.IpFamilies {
		err = v.vpp.PuntRedirect(types.IpPuntRedirect{
			RxSwIfIndex: vpplink.InvalidID,
			Paths: []types.RoutePath{{
				Table:     common.PuntTableId,
				SwIfIndex: types.InvalidID,
			}},
		}, ipFamily.IsIp6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring punt redirect")
		}

		err = v.vpp.PuntAllL4(ipFamily.IsIp6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring L4 punt")
		}
	}

	for _, neigh := range []net.IP{fakeVppNextHopIP4, fakeVppNextHopIP6} {
		err = v.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    tapSwIfIndex,
			IP:           neigh,
			HardwareAddr: ifState.HardwareAddr,
		})
		if err != nil {
			return errors.Wrapf(err, "Error adding neighbor %s to tap", neigh)
		}
		/* In the punt table (where all punted traffics ends), route to the tap */
		err = v.vpp.RouteAdd(&types.Route{
			Table: common.PuntTableId,
			Paths: []types.RoutePath{{
				Gw:        neigh,
				SwIfIndex: tapSwIfIndex,
			}},
		})
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		}
	}

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
func (v *VppRunner) pickNextHopIP(ifState config.LinuxInterfaceState) {
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
		if !addr.IPNet.Contains(nhAddr) {
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

	if !((needsV4 && !foundV4) || (needsV6 && !foundV6)) {
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
}

func (v *VppRunner) configureLinuxTap(link netlink.Link, ifState config.LinuxInterfaceState) (err error) {
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	for _, addr := range ifState.Addresses {
		if addr.IPNet.IP.To4() == nil {
			if err = pod_interface.WriteProcSys("/proc/sys/net/ipv6/conf/"+link.Attrs().Name+"/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf."+link.Attrs().Name+".disable_ipv6=0: %s", err)
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
	v.pickNextHopIP(ifState)
	config.Info.FakeNextHopIP4 = fakeNextHopIP4
	config.Info.FakeNextHopIP6 = fakeNextHopIP6
	return nil
}

func (v *VppRunner) addExtraAddresses(addrList []netlink.Addr, extraAddrCount int, vppIfSwIfIndex uint32) (err error) {
	ipFlowHash := types.FlowHashSrcIP |
		types.FlowHashDstIP |
		types.FlowHashSrcPort |
		types.FlowHashDstPort |
		types.FlowHashSymetric

	err = v.vpp.SetIPFlowHash(ipFlowHash, 0 /* vrf */, false /* isIPv6 */)
	if err != nil {
		log.Errorf("cannot configure flow hash: %v", err)
	}
	/* No v6 as extraAddrCount doesnt support it & flow hash breaks in vpp */

	log.Infof("Adding %d extra addresses", extraAddrCount)
	v4Count := 0
	var addr net.IPNet
	for _, a := range addrList {
		if a.IP.To4() != nil {
			v4Count++
			addr = *a.IPNet
		}
	}
	if v4Count != 1 {
		return fmt.Errorf("%d IPv4 addresses found, not configuring extra addresses (need exactly 1)", v4Count)
	}
	for i := 1; i <= extraAddrCount; i++ {
		a := &net.IPNet{
			IP:   net.IP(append([]byte(nil), addr.IP.To4()...)),
			Mask: addr.Mask,
		}
		a.IP[2] += byte(i)
		err = v.vpp.AddInterfaceAddress(vppIfSwIfIndex, a)
		if err != nil {
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	return nil
}

func (v *VppRunner) allocateStaticVRFs() error {
	// Create all VRFs with a static ID that we use first so that we can
	// then call AllocateVRF without risk of conflict
	for _, ipFamily := range vpplink.IpFamilies {
		err := v.vpp.AddVRF(common.PuntTableId, ipFamily.IsIp6, fmt.Sprintf("punt-table-%s", ipFamily.Str))
		if err != nil {
			return errors.Wrapf(err, "Error creating punt vrf %s", ipFamily.Str)
		}
		err = v.vpp.AddVRF(common.PodVRFIndex, ipFamily.IsIp6, fmt.Sprintf("calico-pods-%s", ipFamily.Str))
		if err != nil {
			return err
		}
		err = v.vpp.AddDefaultRouteViaTable(common.PodVRFIndex, common.DefaultVRFIndex, ipFamily.IsIp6)
		if err != nil {
			return err
		}
	}
	return nil
}

// Configure specific VRFs for a given tap to the host to handle broadcast / multicast traffic sent by the host
func (v *VppRunner) setupTapVRF(ifSpec *config.UplinkInterfaceSpec, ifState *config.LinuxInterfaceState, tapSwIfIndex uint32) (vrfs []uint32, err error) {
	for _, ipFamily := range vpplink.IpFamilies {
		vrfId, err := v.vpp.AllocateVRF(ipFamily.IsIp6, fmt.Sprintf("host-tap-%s-%s", ifSpec.InterfaceName, ipFamily.Str))
		if err != nil {
			return []uint32{}, errors.Wrap(err, "Error allocating vrf for tap")
		}
		if ipFamily.IsIp4 {
			// special route to forward broadcast from the host through the matching uplink
			// useful for instance for DHCP DISCOVER pkts from the host
			err = v.vpp.RouteAdd(&types.Route{
				Table: vrfId,
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
		} // else {} No custom routes for IPv6 for now. Forward LL multicast from the host?

		// default route in default table
		err = v.vpp.AddDefaultRouteViaTable(vrfId, common.DefaultVRFIndex, ipFamily.IsIp6)
		if err != nil {
			return []uint32{}, errors.Wrapf(err, "error adding VRF %d default route via VRF %d", vrfId, common.DefaultVRFIndex)
		}
		// Set tap in this table
		err = v.vpp.SetInterfaceVRF(tapSwIfIndex, vrfId, ipFamily.IsIp6)
		if err != nil {
			return []uint32{}, errors.Wrapf(err, "error setting vpp tap in vrf %d", vrfId)
		}
		vrfs = append(vrfs, vrfId)
	}

	// Configure addresses to enable ipv4 & ipv6 on the tap
	for _, addr := range ifState.Addresses {
		if addr.IPNet.IP.IsLinkLocalUnicast() && !common.IsFullyQualified(addr.IPNet) && common.IsV6Cidr(addr.IPNet) {
			log.Infof("Not adding address %s to data interface (vpp requires /128 link-local)", addr.String())
			continue
		} else {
			log.Infof("Adding address %s to tap interface", addr.String())
		}
		// to max len cidr because we don't want the rest of the subnet to be considered as
		// connected to that interface
		// note that the role of these addresses is just to tell vpp to accept ip4 / ip6 packets on the tap
		// we use these addresses as the safest option, because as they are configured on linux, linux
		// will never send us packets with these addresses as destination
		err = v.vpp.AddInterfaceAddress(tapSwIfIndex, common.ToMaxLenCIDR(addr.IPNet.IP))
		if err != nil {
			log.Errorf("Error adding address to tap interface: %v", err)
		}
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

	for _, addr := range ifState.Addresses {
		if addr.IPNet.IP.IsLinkLocalUnicast() && !common.IsFullyQualified(addr.IPNet) && common.IsV6Cidr(addr.IPNet) {
			log.Infof("Not adding address %s to uplink interface (vpp requires /128 link-local)", addr.String())
			continue
		} else {
			log.Infof("Adding address %s to uplink interface", addr.String())
		}
		err = v.vpp.AddInterfaceAddress(ifSpec.SwIfIndex, addr.IPNet)
		if err != nil {
			log.Errorf("Error adding address to uplink interface: %v", err)
		}
	}
	for _, route := range ifState.Routes {
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

	if ifSpec.GetIsMain() {
		if config.GetCalicoVppInitialConfig().ExtraAddrCount > 0 {
			err = v.addExtraAddresses(ifState.Addresses, config.GetCalicoVppInitialConfig().ExtraAddrCount, ifSpec.SwIfIndex)
			if err != nil {
				log.Errorf("Cannot configure requested extra addresses: %v", err)
			}
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
			HardwareAddr:      vppSideMac,
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

	vrfs, err := v.setupTapVRF(&ifSpec, ifState, tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error configuring VRF for tap")
	}

	// Always set this tap on worker 0
	err = v.vpp.SetInterfaceRxPlacement(tapSwIfIndex, 0 /*queue*/, 0 /*worker*/, false /*main*/)
	if err != nil {
		return errors.Wrap(err, "Error setting tap rx placement")
	}

	err = v.vpp.SetInterfaceMtu(uint32(tapSwIfIndex), vpplink.MAX_MTU)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on tap interface", vpplink.MAX_MTU)
	}

	if ifState.Hasv6 {
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

	for _, addr := range ifState.Addresses {
		if addr.IPNet.IP.To4() == nil {
			log.Infof("Adding ND proxy for address %s", addr.IPNet.IP)
			err = v.vpp.EnableIP6NdProxy(tapSwIfIndex, addr.IPNet.IP)
			if err != nil {
				log.Errorf("Error configuring nd proxy for address %s: %v", addr.IPNet.IP.String(), err)
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

	// Linux side tap setup
	link, err := netlink.LinkByName(ifSpec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", ifSpec.InterfaceName)
	}

	err = v.configureLinuxTap(link, *ifState)
	if err != nil {
		return errors.Wrap(err, "Error configuring tap on linux side")
	}

	err = v.vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	if config.Info.UplinkStatuses != nil {
		config.Info.UplinkStatuses = append(config.Info.UplinkStatuses, config.UplinkStatus{
			TapSwIfIndex: tapSwIfIndex,
			SwIfIndex:    ifSpec.SwIfIndex,
			Mtu:          uplinkMtu,
			LinkIndex:    link.Attrs().Index,
			Name:         link.Attrs().Name,
			IsMain:       ifSpec.GetIsMain(),
		})
	}
	return nil
}

func (v *VppRunner) doVppGlobalConfiguration() (err error) {
	err = v.allocateStaticVRFs()
	if err != nil {
		return errors.Wrap(err, "Error creating static VRFs in VPP")
	}

	err = v.vpp.SetK8sSnatPolicy()
	if err != nil {
		return errors.Wrap(err, "Error configuring cnat source policy")
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
			log.Infof("Updating node, version = %s, metaversion = %s", node.ResourceVersion, node.ObjectMeta.ResourceVersion)
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

	/**
	 * From this point it is very important that every exit
	 * path calls restoreConfiguration after vpp exits */
	defer v.restoreConfiguration(v.allInterfacesPhysical())

	log.Infof("VPP started [PID %d]", vppProcess.Pid)
	runningCond.Broadcast()

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(config.GetCalicoVppInitialConfig().VppStartupSleepSeconds) * time.Second)

	vpp, err := utils.CreateVppLink()
	v.vpp = vpp
	if err != nil {
		terminateVpp("Error connecting to VPP: %v", err)
		v.vpp.Close()
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
	var t tomb.Tomb

	// close vpp as we do not program
	v.vpp.Close()
	hooks.RunHook(hooks.VPP_RUNNING, v.params, v.conf)

	<-vppDeadChan
	log.Infof("VPP Exited: status %v", err)

	err = t.Killf("Vpp exited, stopping watchers")
	if err != nil {
		log.Errorf("Error Killf vpp: %v", err)
	}
	return nil
}

func (v *VppRunner) restoreConfiguration(allInterfacesPhysical bool) {
	log.Infof("Restoring configuration")
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
