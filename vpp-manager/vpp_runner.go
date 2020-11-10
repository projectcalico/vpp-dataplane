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
	"github.com/projectcalico/vpp-dataplane/vpp-manager/startup"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/uplink"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type VppRunner struct {
	params *startup.VppManagerParams
	conf   *startup.InterfaceConfig
	vpp    *vpplink.VppLink
}

func NewVPPRunner(params *startup.VppManagerParams, conf *startup.InterfaceConfig) *VppRunner {
	return &VppRunner{
		params: params,
		conf:   conf,
	}
}

func (v *VppRunner) Run() {
	err := v.generateVppConfigExecFile()
	if err != nil {
		log.Fatalf("Error generating VPP config Exec: %s", err)
	}

	err = v.generateVppConfigFile()
	if err != nil {
		log.Fatalf("Error generating VPP config: %s", err)
	}

	err = v.preConfigureLinuxMainInterface()
	if err != nil {
		log.Fatalf("Error pre-configuring Linux main IF: %s", err)
	}

	err = v.runVpp()
	if err != nil {
		log.Errorf("Error running VPP: %v", err)
	}
}

func (v *VppRunner) restoreLinuxConfig() (err error) {
	// No need to delete the tap we created with VPP since it should disappear with all its configuration
	// when VPP dies
	if v.conf.PciId != "" && v.conf.Driver != "" {
		err := utils.SwapDriver(v.conf.PciId, v.conf.Driver, false)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", v.conf.Driver, v.conf.PciId, err)
		}
	}
	if !v.conf.IsUp {
		return nil
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	retries := 0
	failed := false
	var link netlink.Link
	for {
		link, err = netlink.LinkByName(v.params.MainInterface)
		if err != nil {
			retries += 1
			if retries >= 10 {
				return errors.Wrapf(err, "Error finding link %s after %d tries", v.params.MainInterface, retries)
			}
			time.Sleep(500 * time.Millisecond)
		} else {
			log.Infof("found links %s after %d tries", v.params.MainInterface, retries)
			break
		}
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s back up", v.params.MainInterface)
	}
	/* Restore XDP specific settings */
	if v.params.NativeDriver == uplink.NATIVE_DRIVER_AF_XDP {
		log.Infof("Removing AF XDP conf")
		if !v.conf.PromiscOn {
			log.Infof("Setting promisc off")
			err = netlink.SetPromiscOff(link)
			if err != nil {
				log.Errorf("Error setting link %s promisc off %v", v.params.MainInterface, err)
				failed = true
			}
		}
		if v.conf.NumRxQueues != v.params.NumRxQueues {
			log.Infof("Setting back %d queues", v.conf.NumRxQueues)
			err = utils.SetInterfaceRxQueues(v.params.MainInterface, v.conf.NumRxQueues)
			if err != nil {
				log.Errorf("Error setting link %s NumQueues to %d %v", v.params.MainInterface, v.conf.NumRxQueues, err)
				failed = true
			}
		}
	}
	// Re-add all adresses and routes
	for _, addr := range v.conf.Addresses {
		if vpplink.IsIP6(addr.IP) && addr.IP.IsLinkLocalUnicast() {
			log.Infof("Skipping linklocal address %s", addr.String())
			continue
		}
		log.Infof("restoring address %s", addr.String())
		err := netlink.AddrAdd(link, &addr)
		if err != nil {
			log.Errorf("cannot add address %+v back to %s : %+v", addr, link.Attrs().Name, err)
			failed = true
			// Keep going for the rest of the config
		}
	}
	for _, route := range v.conf.Routes {
		if utils.RouteIsLinkLocalUnicast(&route) {
			log.Infof("Skipping linklocal route %s", route.String())
			continue
		}
		log.Infof("restoring route %s", route.String())
		route.LinkIndex = link.Attrs().Index
		err := netlink.RouteAdd(&route)
		if err != nil {
			log.Errorf("cannot add route %+v back to %s : %+v", route, link.Attrs().Name, err)
			failed = true
			// Keep going for the rest of the config
		}
	}
	if failed {
		return fmt.Errorf("reconfiguration of some addresses or routes failed for %s", link.Attrs().Name)
	}
	return nil
}

func (v *VppRunner) removeInitialRoutes(link netlink.Link) {
	for _, route := range v.conf.Routes {
		log.Infof("deleting Route %s", route.String())
		err := netlink.RouteDel(&route)
		if err != nil {
			log.Errorf("cannot delete route %+v: %+v", route, err)
			// Keep going for the rest of the config
		}
	}
	for _, addr := range v.conf.Addresses {
		err := netlink.AddrDel(link, &addr)
		if err != nil {
			log.Errorf("Error adding address %s to tap interface : %+v", addr, err)
		}
	}
}

func (v *VppRunner) configurePunt(tapSwIfIndex uint32) (err error) {
	if v.conf.Hasv4 {
		err := v.vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, net.ParseIP("0.0.0.0"))
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 punt")
		}
		err = v.vpp.PuntAllL4(false)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 L4 punt")
		}
	}
	if v.conf.Hasv6 {
		err := v.vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, net.ParseIP("::"))
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

func (v *VppRunner) safeAddInterfaceAddress(swIfIndex uint32, addr *net.IPNet) (err error) {
	maskSize, _ := addr.Mask.Size()
	if vpplink.IsIP6(addr.IP) && maskSize != 128 && addr.IP.IsLinkLocalUnicast() {
		err = v.vpp.AddInterfaceAddress(swIfIndex, &net.IPNet{
			IP:   addr.IP,
			Mask: utils.GetMaxCIDRMask(addr.IP),
		})
		if err != nil {
			return err
		}
		log.Infof("Adding extra route to %s for %d mask", addr, maskSize)
		return v.vpp.RouteAdd(&types.Route{
			Dst: addr,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		})
	}
	return v.vpp.AddInterfaceAddress(swIfIndex, addr)
}

func (v *VppRunner) configureLinuxTap(link netlink.Link) (err error) {
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting tap %s up", config.HostIfName)
	}
	// Add /32 or /128 for each address configured on VPP side
	for _, addr := range v.conf.Addresses {
		singleAddr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   addr.IP,
				Mask: utils.GetMaxCIDRMask(addr.IP),
			},
			Label: config.HostIfName,
		}
		log.Infof("Adding address %+v to tap interface", singleAddr)
		err = netlink.AddrAdd(link, &singleAddr)
		if err != nil {
			return errors.Wrapf(err, "Error adding address %s to tap interface", singleAddr)
		}
	}
	// All routes that were on this interface now go through VPP
	for _, route := range v.conf.Routes {
		newRoute := netlink.Route{
			Dst:       route.Dst,
			LinkIndex: link.Attrs().Index,
		}
		log.Infof("Adding route %s via VPP", newRoute)
		err = netlink.RouteAdd(&newRoute)
		if err == syscall.EEXIST {
			log.Warnf("cannot add route %+v via vpp, %+v", newRoute, err)
		} else if err != nil {
			return errors.Wrapf(err, "cannot add route %+v via vpp", newRoute)
		}
	}

	for _, serviceCIDR := range v.params.ServiceCIDRs {
		// Add a route for the service prefix through VPP
		log.Infof("Adding route to service prefix %s through VPP", serviceCIDR.String())
		err = netlink.RouteAdd(&netlink.Route{
			Dst:       &serviceCIDR,
			LinkIndex: link.Attrs().Index,
		})
		if err != nil {
			return errors.Wrapf(err, "cannot add tun route to service %s", serviceCIDR.String())
		}
	}
	return nil
}

func (v *VppRunner) addExtraAddresses(addrList []netlink.Addr, extraAddrCount int) (err error) {
	if extraAddrCount == 0 {
		return nil
	}
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
		err = v.safeAddInterfaceAddress(config.DataInterfaceSwIfIndex, a)
		if err != nil {
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	return nil
}

func (v *VppRunner) configureVpp() (err error) {
	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	err = v.vpp.EnableGSOFeature(config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling GSO on data interface")
	}

	err = v.vpp.SetInterfaceRxMode(config.DataInterfaceSwIfIndex, types.AllQueues, v.params.RxMode)
	if err != nil {
		log.Warnf("%v", err)
	}

	err = v.vpp.EnableInterfaceIP6(config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling ip6 on if")
	}

	for _, addr := range v.conf.Addresses {
		log.Infof("Adding address %s to data interface", addr.String())
		err = v.safeAddInterfaceAddress(config.DataInterfaceSwIfIndex, addr.IPNet)
		if err != nil {
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	for _, route := range v.conf.Routes {
		// Only add routes with a next hop, assume the others come from interface addresses
		if utils.RouteIsLinkLocalUnicast(&route) {
			log.Infof("Skipping linklocal route %s", route.String())
			continue
		}
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
	err = v.addExtraAddresses(v.conf.Addresses, v.params.ExtraAddrCount)
	if err != nil {
		log.Errorf("Cannot configure requested extra addresses: %v", err)
	}
	err = v.vpp.SetIPFlowHash(0, false, true, true, true, true, false, false, true)
	if err != nil {
		log.Errorf("cannot configure flow hash: %v", err)
	}
	err = v.vpp.SetIPFlowHash(0, true, true, true, true, true, false, false, true)
	if err != nil {
		log.Errorf("cannot configure flow hash: %v", err)
	}

	// If main interface is still up flush its routes or they'll conflict with $HostIfName
	link, err := netlink.LinkByName(v.params.MainInterface)
	if err == nil {
		isUp := (link.Attrs().Flags & net.FlagUp) != 0
		if isUp {
			v.removeInitialRoutes(link)
		}
	}

	log.Infof("Creating Linux side interface")
	tapSwIfIndex, err := v.vpp.CreateTapV2(&types.TapV2{
		HostIfName:     config.HostIfName,
		Tag:            config.HostIfTag,
		MacAddress:     v.params.VppSideMacAddress,
		HostMacAddress: v.params.ContainerSideMacAddress,
		RxQueueSize:    v.params.TapRxQueueSize,
		TxQueueSize:    v.params.TapTxQueueSize,
		Flags:          types.TapFlagTun,
	})
	if err != nil {
		return errors.Wrap(err, "Error creating tap")
	}
	err = utils.WriteFile(strconv.FormatInt(int64(tapSwIfIndex), 10), config.VppManagerTapIdxFile)
	if err != nil {
		return errors.Wrap(err, "Error writing tap idx")
	}

	err = v.vpp.SetInterfaceRxMode(tapSwIfIndex, types.AllQueues, v.params.TapRxMode)
	if err != nil {
		log.Errorf("Error SetInterfaceRxMode on vpptap0 %v", err)
	}

	err = v.configurePunt(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error adding redirect to tap")
	}

	err = v.vpp.InterfaceSetUnnumbered(tapSwIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting vpp tap unnumbered")
	}

	// Linux side tap setup
	link, err = netlink.LinkByName(config.HostIfName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", config.HostIfName)
	}

	err = v.configureLinuxTap(link)
	if err != nil {
		return errors.Wrap(err, "Error configure tap linux side")
	}

	err = v.vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	// TODO should watch for service prefix and ip pools to always route them through VPP
	// Service prefix is needed even if kube-proxy is running on the host to ensure correct source address selection
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

func (v *VppRunner) CreateNativeMainInterface() (err error) {
	swIfIndex := ^uint32(0)
	if v.params.NativeDriver == uplink.NATIVE_DRIVER_AF_PACKET {
		v.conf.PciId = ""
		v.conf.Driver = ""
		swIfIndex, err = v.vpp.CreateAfPacket(v.params.MainInterface, &v.conf.HardwareAddr)
	} else if v.params.NativeDriver == uplink.NATIVE_DRIVER_AF_XDP {
		v.conf.PciId = ""
		v.conf.Driver = ""
		intf := types.VppXDPInterface{
			HostInterfaceName: v.params.MainInterface,
			RxQueueSize:       v.params.RxQueueSize,
			TxQueueSize:       v.params.TxQueueSize,
			NumRxQueues:       v.params.NumRxQueues,
		}
		err = v.vpp.CreateAfXDP(&intf)
		swIfIndex = intf.SwIfIndex
	} else if v.params.NativeDriver == uplink.NATIVE_DRIVER_VIRTIO {
		swIfIndex, err = v.vpp.CreateVirtio(v.conf.PciId, &v.conf.HardwareAddr)
	} else {
		return fmt.Errorf("Unkown native driver: %s", v.params.NativeDriver)
	}

	if err != nil {
		return errors.Wrapf(err, "Error creating %s native interface", v.params.NativeDriver)
	}
	log.Infof("Created %s native interface %d", v.params.NativeDriver, swIfIndex)

	if swIfIndex != config.DataInterfaceSwIfIndex {
		return fmt.Errorf("Created %s interface has wrong swIfIndex %d!", v.params.NativeDriver, swIfIndex)
	}
	return nil
}

func (v *VppRunner) preConfigureLinuxMainInterface() (err error) {
	if v.conf.IsUp && v.params.NativeDriver != uplink.NATIVE_DRIVER_AF_XDP {
		// Set interface down if it is up, bind it to a VPP-friendly driver
		link, err := netlink.LinkByName(v.params.MainInterface)
		if err != nil {
			return errors.Wrapf(err, "Error finding link %s", v.params.MainInterface)
		}
		err = netlink.LinkSetDown(link)
		if err != nil {
			// In case it still succeeded
			netlink.LinkSetUp(link)
			return errors.Wrapf(err, "Error setting link %s down", v.params.MainInterface)
		}
	}
	if v.conf.DoSwapDriver {
		if v.conf.PciId == "" {
			log.Warnf("PCI ID not found, not swapping drivers")
		} else {
			err = utils.SwapDriver(v.conf.PciId, v.params.NewDriverName, true)
			if err != nil {
				log.Warnf("Failed to swap driver to %s: %v", v.params.NewDriverName, err)
			}
		}
	}
	if v.params.NativeDriver == uplink.NATIVE_DRIVER_AF_XDP {
		link, err := netlink.LinkByName(v.params.MainInterface)
		if err != nil {
			return errors.Wrapf(err, "Error finding link %s", v.params.MainInterface)
		}
		err = netlink.SetPromiscOn(link)
		if err != nil {
			return errors.Wrapf(err, "Error setting link %s promisc on", v.params.MainInterface)
		}
		err = utils.SetInterfaceRxQueues(v.params.MainInterface, v.params.NumRxQueues)
		if err != nil {
			return errors.Wrapf(err, "Error setting link %s NumQueues to %d", v.params.MainInterface, v.params.NumRxQueues)
		}
	}
	return nil
}

// Returns VPP exit code
func (v *VppRunner) runVpp() (err error) {
	// From this point it is very important that every exit path calls restoreLinuxConfig after vpp exits
	// Bind the interface to a suitable drivr for VPP. DPDK does it automatically, this is useful otherwise
	vppCmd = exec.Command(config.VppPath, "-c", config.VppConfigFile)
	vppCmd.Stdout = os.Stdout
	vppCmd.Stderr = os.Stderr
	err = vppCmd.Start()
	if err != nil {
		v.restoreConfiguration()
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
		v.restoreConfiguration()
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}

	if v.params.NativeDriver != uplink.NATIVE_DRIVER_NONE {
		err = v.vpp.Retry(2*time.Second, 10, v.CreateNativeMainInterface)
		if err != nil {
			terminateVpp("Error creating af_packet (SIGINT %d): %v", vppProcess.Pid, err)
			v.vpp.Close()
			<-vppDeadChan
			v.restoreConfiguration()
			return errors.Wrap(err, "Error creating af_packet")
		}
	}

	// Data interface configuration
	err = v.vpp.Retry(2*time.Second, 10, v.vpp.InterfaceAdminUp, config.DataInterfaceSwIfIndex)
	if err != nil {
		terminateVpp("Error setting main interface up (SIGINT %d): %v", vppProcess.Pid, err)
		v.vpp.Close()
		<-vppDeadChan
		v.restoreConfiguration()
		return errors.Wrap(err, "Error setting data interface up")
	}

	// Configure VPP
	err = v.configureVpp()
	v.vpp.Close()
	if err != nil {
		<-vppDeadChan
		terminateVpp("Error configuring VPP (SIGINT %d): %v", vppProcess.Pid, err)
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = v.updateCalicoNode()
	if err != nil {
		terminateVpp("Error updating Calico node (SIGINT %d): %v", vppProcess.Pid, err)
		<-vppDeadChan
		v.restoreConfiguration()
		return errors.Wrap(err, "Error updating Calico node")
	}

	go syncPools()

	utils.WriteFile("1", config.VppManagerStatusFile)
	<-vppDeadChan
	log.Infof("VPP Exited: status %v", err)
	v.restoreConfiguration()
	return nil
}

func (v *VppRunner) restoreConfiguration() {
	log.Infof("Restoring configuration")
	err := utils.ClearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing vpp manager files: %v", err)
	}
	err = v.restoreLinuxConfig()
	if err != nil {
		log.Errorf("Error restoring linux config: %v", err)
	}
	err = v.pingCalicoVpp()
	if err != nil {
		log.Errorf("Error pinging calico-vpp: %v", err)
	}
}

func (v *VppRunner) generateVppConfigExecFile() error {
	if v.params.ConfigExecTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(v.params.ConfigExecTemplate, "__PCI_DEVICE_ID__", v.conf.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", v.params.MainInterface)
	err := errors.Wrapf(
		ioutil.WriteFile(config.VppConfigExecFile, []byte(template+"\n"), 0744),
		"Error writing VPP Exec configuration to %s",
		config.VppConfigExecFile,
	)
	return err
}

func (v *VppRunner) generateVppConfigFile() error {
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(v.params.ConfigTemplate, "__PCI_DEVICE_ID__", v.conf.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", v.params.MainInterface)
	return errors.Wrapf(
		ioutil.WriteFile(config.VppConfigFile, []byte(template+"\n"), 0644),
		"Error writing VPP configuration to %s",
		config.VppConfigFile,
	)
}
