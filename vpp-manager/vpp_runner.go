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
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoopts "github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/uplink"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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
	conf         *config.InterfaceConfig
	vpp          *vpplink.VppLink
	uplinkDriver uplink.UplinkDriver
	routeWatcher *RouteWatcher
	poolWatcher  *PoolWatcher
	linkWatcher  *LinkWatcher
}

func NewVPPRunner(params *config.VppManagerParams, conf *config.InterfaceConfig) *VppRunner {
	return &VppRunner{
		params: params,
		conf:   conf,
	}
}

func (v *VppRunner) Run(driver uplink.UplinkDriver) error {
	v.uplinkDriver = driver
	log.Infof("Running with uplink %s", driver.GetName())

	err := v.uplinkDriver.GenerateVppConfigExecFile()
	if err != nil {
		return errors.Wrapf(err, "Error generating VPP config Exec: %s")
	}

	err = v.uplinkDriver.GenerateVppConfigFile()
	if err != nil {
		return errors.Wrapf(err, "Error generating VPP config: %s")
	}

	err = v.uplinkDriver.PreconfigureLinux()
	if err != nil {
		return errors.Wrapf(err, "Error pre-configuring Linux main IF: %s")
	}

	hooks.RunHook(hooks.BEFORE_VPP_RUN, v.params, v.conf)
	err = v.runVpp()
	if err != nil {
		return errors.Wrapf(err, "Error running VPP: %v")
	}
	hooks.RunHook(hooks.VPP_DONE_OK, v.params, v.conf)
	return nil
}

func (v *VppRunner) configurePunt(tapSwIfIndex uint32) (err error) {
	if v.conf.Hasv4 {
		err := v.vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, fakeVppNextHopIP4)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 punt")
		}
		err = v.vpp.PuntAllL4(false)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 L4 punt")
		}
	}
	if v.conf.Hasv6 {
		err := v.vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, fakeVppNextHopIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv6 punt")
		}
		err = v.vpp.PuntAllL4(true)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv6 L4 punt")
		}
	}
	return nil
}

func (v *VppRunner) hasAddr(ip net.IP) bool {
	for _, addr := range v.conf.Addresses {
		if ip.Equal(addr.IP) {
			return true
		}
	}
	return false
}

// pick a next hop to use for cluster routes (services, pod cidrs) in the address prefix
func (v *VppRunner) pickNextHopIP() {
	var nhAddr net.IP
	foundV4, foundV6 := false, false
	needsV4, needsV6 := false, false

	for _, addr := range v.conf.Addresses {
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

	for _, route := range v.conf.Routes {
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
				if v.hasAddr(nhAddr) {
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
				if v.hasAddr(nhAddr) {
					nhAddr = utils.IncrementIP(utils.NetworkAddr(route.Dst))
				}
				log.Infof("Using %s as next hop for cluster IPv6 routes (from directly connected route)", route.Dst.IP.String())
				fakeNextHopIP6 = nhAddr
				foundV6 = true
			}
		}
	}
}

func (v *VppRunner) configureLinuxTap(link netlink.Link) (err error) {
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting tap %s up", config.HostIfName)
	}

	// Configure original addresses and routes on the new tap
	for _, addr := range v.conf.Addresses {
		log.Infof("Adding address %+v to tap interface", addr)
		err = netlink.AddrAdd(link, &addr)
		if err == syscall.EEXIST {
			log.Warnf("add addr %+v via vpp EEXIST, %+v", addr, err)
		} else if err != nil {
			return errors.Wrapf(err, "Error adding address %s to tap interface", addr)
		}
	}
	for _, route := range v.conf.Routes {
		route.LinkIndex = link.Attrs().Index
		log.Infof("Adding route %s via VPP", route)
		err = netlink.RouteAdd(&route)
		if err == syscall.EEXIST {
			log.Warnf("add route %+v via vpp EEXIST, %+v", route, err)
		} else if err != nil {
			return errors.Wrapf(err, "cannot add route %+v via vpp", route)
		}
	}

	// Determine a suitable next hop for the cluster routes
	v.pickNextHopIP()

	for _, serviceCIDR := range v.params.ServiceCIDRs {
		// Add a route for the service prefix through VPP. This is required even if kube-proxy is
		// running on the host to ensure correct source address selection if the host has multiple interfaces
		log.Infof("Adding route to service prefix %s through VPP", serviceCIDR.String())
		gw := fakeNextHopIP4
		if serviceCIDR.IP.To4() == nil {
			gw = fakeNextHopIP6
		}
		err = v.routeWatcher.AddRoute(&netlink.Route{
			Dst:      &serviceCIDR,
			Gw:       gw,
			Protocol: syscall.RTPROT_STATIC,
			MTU:      config.GetUplinkMtu(v.params, v.conf, true /* includeEncap */),
		})
		if err != nil {
			return errors.Wrapf(err, "cannot add tap route to service %s", serviceCIDR.String())
		}
	}
	return nil
}

func (v *VppRunner) addExtraAddresses(addrList []netlink.Addr, extraAddrCount int) (err error) {
	ipFlowHash := &types.IPFlowHash{
		Src:       true,
		Dst:       true,
		SrcPort:   true,
		DstPort:   true,
		Symmetric: true,
	}

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
		err = v.vpp.AddInterfaceAddress(config.DataInterfaceSwIfIndex, a)
		if err != nil {
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	return nil
}

func (v *VppRunner) configureVpp() (err error) {
	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	if v.params.EnableGSO {
		err = v.vpp.EnableGSOFeature(config.DataInterfaceSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on data interface")
		}
	}

	uplinkMtu := config.GetUplinkMtu(v.params, v.conf, false /* includeEncap */)
	err = v.vpp.SetInterfaceMtu(config.DataInterfaceSwIfIndex, uplinkMtu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on data interface", uplinkMtu)
	}

	err = v.vpp.SetInterfaceRxMode(config.DataInterfaceSwIfIndex, types.AllQueues, v.params.RxMode)
	if err != nil {
		log.Warnf("%v", err)
	}

	err = v.vpp.EnableInterfaceIP6(config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling ip6 on if")
	}

	err = v.vpp.CnatEnableFeatures(config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error configuring NAT on uplink interface")
	}

	// special route to forward broadcast dhcp packets from the host
	err = v.vpp.RouteAdd(&types.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4bcast,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
		Paths: []types.RoutePath{{
			Gw:        net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
			SwIfIndex: config.DataInterfaceSwIfIndex,
		}},
	})
	if err != nil {
		log.Errorf("cannot add broadcast route in vpp: %v", err)
	}

	for _, addr := range v.conf.Addresses {
		log.Infof("Adding address %s to data interface", addr.String())
		err = v.vpp.AddInterfaceAddress(config.DataInterfaceSwIfIndex, addr.IPNet)
		if err != nil {
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	for _, route := range v.conf.Routes {
		err = v.vpp.RouteAdd(&types.Route{
			Dst: route.Dst,
			Paths: []types.RoutePath{{
				Gw:        route.Gw,
				SwIfIndex: config.DataInterfaceSwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("cannot add route in vpp: %v", err)
		}
	}
	for _, defaultGW := range v.params.DefaultGWs {
		log.Infof("Adding default route to %s", defaultGW.String())
		err = v.vpp.RouteAdd(&types.Route{
			Paths: []types.RoutePath{{
				Gw:        defaultGW,
				SwIfIndex: config.DataInterfaceSwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("cannot add default route via %s in vpp: %v", defaultGW, err)
		}
	}

	if v.params.ExtraAddrCount > 0 {
		err = v.addExtraAddresses(v.conf.Addresses, v.params.ExtraAddrCount)
		if err != nil {
			log.Errorf("Cannot configure requested extra addresses: %v", err)
		}
	}

	log.Infof("Creating Linux side interface")
	vpptap0Flags := types.TapFlagNone
	if v.params.EnableGSO {
		vpptap0Flags = vpptap0Flags | types.TapFlagGSO | types.TapGROCoalesce
	}

	tapSwIfIndex, err := v.vpp.CreateTapV2(&types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			HostInterfaceName: v.params.MainInterface,
			RxQueueSize:       v.params.TapRxQueueSize,
			TxQueueSize:       v.params.TapTxQueueSize,
			HardwareAddr:      &vppSideMac,
		},
		HostNamespace:  "pid:1", // create tap in root netns
		Tag:            config.HostIfTag,
		Flags:          vpptap0Flags,
		HostMtu:        uplinkMtu,
		HostMacAddress: v.conf.HardwareAddr,
	})
	if err != nil {
		return errors.Wrap(err, "Error creating tap")
	}

	// Always set this tap on worker 0
	err = v.vpp.SetInterfaceRxPlacement(uint32(tapSwIfIndex), uint32(0), uint32(0), false)
	if err != nil {
		return errors.Wrap(err, "Error setting tap rx placement")
	}

	err = v.vpp.SetInterfaceMtu(uint32(tapSwIfIndex), config.VppTapMtu)
	if err != nil {
		return errors.Wrapf(err, "Error setting %d MTU on tap interface", config.VppTapMtu)
	}

	err = utils.WriteFile(strconv.FormatInt(int64(tapSwIfIndex), 10), config.VppManagerTapIdxFile)
	if err != nil {
		return errors.Wrap(err, "Error writing linux mtu")
	}

	err = utils.WriteFile(strconv.FormatInt(int64(uplinkMtu), 10), config.VppManagerLinuxMtu)
	if err != nil {
		return errors.Wrap(err, "Error writing tap idx")
	}

	err = v.vpp.EnableInterfaceIP6(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling ip6 on vpptap0")
	}

	err = v.vpp.DisableIP6RouterAdvertisements(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error disabling ip6 RA on vpptap0")
	}

	for _, neigh := range []net.IP{fakeVppNextHopIP4, fakeVppNextHopIP6} {
		err = v.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    tapSwIfIndex,
			IP:           neigh,
			HardwareAddr: v.conf.HardwareAddr,
		})
		if err != nil {
			return errors.Wrapf(err, "Error adding neighbor %v to tap", neigh)
		}
	}

	err = v.configurePunt(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error adding redirect to tap")
	}

	err = v.vpp.EnableArpProxy(tapSwIfIndex, 0 /* table id */)
	if err != nil {
		return errors.Wrap(err, "Error enabling ARP proxy")
	}

	for _, addr := range v.conf.Addresses {
		if addr.IPNet.IP.To4() == nil {
			log.Infof("Adding ND proxy for address %s", addr.IPNet.IP)
			err = v.vpp.EnableIP6NdProxy(tapSwIfIndex, addr.IPNet.IP)
			if err != nil {
				log.Errorf("Error configuring nd proxy for address %s: %v", addr.IPNet.IP.String(), err)
			}
		}
	}

	if v.params.EnableGSO {
		err = v.vpp.EnableGSOFeature(tapSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on vpptap0")
		}
	}

	err = v.vpp.InterfaceSetUnnumbered(tapSwIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting vpp tap unnumbered")
	}

	err = v.vpp.SetInterfaceRxMode(tapSwIfIndex, types.AllQueues, v.params.TapRxMode)
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

	err = v.vpp.SetK8sSnatPolicy()
	if err != nil {
		return errors.Wrap(err, "Error configuring cnat source policy")
	}

	// Linux side tap setup
	link, err := netlink.LinkByName(v.params.MainInterface)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", v.params.MainInterface)
	}

	err = v.configureLinuxTap(link)
	if err != nil {
		return errors.Wrap(err, "Error configuring tap on linux side")
	}

	err = v.vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	if v.params.UserSpecifiedMtu != 0 {
		v.linkWatcher = &LinkWatcher{
			LinkIndex: link.Attrs().Index,
			LinkName:  link.Attrs().Name,
			MTU:       uplinkMtu,
		}
	}
	return nil
}

func (v *VppRunner) updateCalicoNode() (err error) {
	var node, updated *calicoapi.Node
	var client calicocli.Interface
	// TODO create if doesn't exist? need to be careful to do it atomically... and everyone else must as well.
	for i := 0; i < 10; i++ {
		client, err = calicocli.NewFromEnv()
		if err != nil {
			return errors.Wrap(err, "Error creating calico client")
		}
		ctx, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel1()
		node, err = client.Nodes().Get(ctx, v.params.NodeName, calicoopts.GetOptions{})
		if err != nil {
			log.Warnf("Try [%d/10] cannot get current node from Calico %+v", i, err)
			time.Sleep(1 * time.Second)
			continue
		}
		// Update node with address
		needUpdate := false
		if node.Spec.BGP == nil {
			node.Spec.BGP = &calicoapi.NodeBGPSpec{}
		}
		if v.conf.Hasv4 {
			log.Infof("Setting BGP nodeIP %s", v.conf.NodeIP4)
			if node.Spec.BGP.IPv4Address != v.conf.NodeIP4 {
				node.Spec.BGP.IPv4Address = v.conf.NodeIP4
				needUpdate = true
			}
		}
		if v.conf.Hasv6 {
			log.Infof("Setting BGP nodeIP %s", v.conf.NodeIP6)
			if node.Spec.BGP.IPv6Address != v.conf.NodeIP6 {
				node.Spec.BGP.IPv6Address = v.conf.NodeIP6
				needUpdate = true
			}
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
	dat, err := ioutil.ReadFile(config.CalicoVppPidFile)
	if err != nil {
		return errors.Wrapf(err, "Error reading %s", config.CalicoVppPidFile)
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 64)
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

// Returns VPP exit code
func (v *VppRunner) runVpp() (err error) {
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
	defer v.restoreConfiguration()
	if err != nil {
		return errors.Wrap(err, "Error starting vpp process")
	}
	vppProcess = vppCmd.Process
	log.Infof("VPP started [PID %d]", vppProcess.Pid)
	runningCond.Broadcast()

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(v.params.VppStartupSleepSeconds) * time.Second)

	vpp, err := utils.CreateVppLink()
	v.vpp = vpp
	if err != nil {
		terminateVpp("Error connecting to VPP (SIGINT %d): %v", vppProcess.Pid, err)
		v.vpp.Close()
		<-vppDeadChan
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}

	err = v.uplinkDriver.CreateMainVppInterface(vpp, vppProcess.Pid)
	if err != nil {
		terminateVpp("Error creating main interface (SIGINT %d): %v", vppProcess.Pid, err)
		v.vpp.Close()
		<-vppDeadChan
		return errors.Wrap(err, "Error creating main interface")
	}

	// Data interface configuration
	err = v.vpp.Retry(2*time.Second, 10, v.vpp.InterfaceAdminUp, config.DataInterfaceSwIfIndex)
	if err != nil {
		terminateVpp("Error setting main interface up (SIGINT %d): %v", vppProcess.Pid, err)
		v.vpp.Close()
		<-vppDeadChan
		return errors.Wrap(err, "Error setting data interface up")
	}

	v.routeWatcher = &RouteWatcher{}
	v.poolWatcher = &PoolWatcher{
		RouteWatcher: v.routeWatcher,
		params:       v.params,
		conf:         v.conf,
	}
	go v.routeWatcher.WatchRoutes()

	// Configure VPP
	err = v.configureVpp()
	v.vpp.Close()
	if err != nil {
		terminateVpp("Error configuring VPP (SIGINT %d): %v", vppProcess.Pid, err)
		<-vppDeadChan
		return errors.Wrap(err, "Error configuring VPP")
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = v.updateCalicoNode()
	if err != nil {
		terminateVpp("Error updating Calico node (SIGINT %d): %v", vppProcess.Pid, err)
		<-vppDeadChan
		return errors.Wrap(err, "Error updating Calico node")
	}

	utils.WriteFile("1", config.VppManagerStatusFile)
	go v.poolWatcher.SyncPools()
	if v.linkWatcher != nil {
		go v.linkWatcher.WatchLinks()
	}

	hooks.RunHook(hooks.VPP_RUNNING, v.params, v.conf)

	<-vppDeadChan
	log.Infof("VPP Exited: status %v", err)

	v.poolWatcher.Stop()
	v.routeWatcher.Stop()
	if v.linkWatcher != nil {
		v.linkWatcher.Stop()
	}
	return nil
}

func (v *VppRunner) restoreConfiguration() {
	log.Infof("Restoring configuration")
	err := utils.ClearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing vpp manager files: %v", err)
	}
	v.uplinkDriver.RestoreLinux()
	err = v.pingCalicoVpp()
	if err != nil {
		log.Errorf("Error pinging calico-vpp: %v", err)
	}
}
