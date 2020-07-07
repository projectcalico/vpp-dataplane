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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoopts "github.com/projectcalico/libcalico-go/lib/options"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	DataInterfaceSwIfIndex        = uint32(1) // Assumption: the VPP config ensures this is true
	VppConfigFile                 = "/etc/vpp/startup.conf"
	VppConfigExecFile             = "/etc/vpp/startup.exec"
	VppManagerStatusFile          = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile          = "/var/run/vpp/vppmanagertap0"
	VppApiSocket                  = "/var/run/vpp/vpp-api.sock"
	CalicoVppPidFile              = "/var/run/vpp/calico_vpp.pid"
	VppPath                       = "/usr/bin/vpp"
	NodeNameEnvVar                = "NODENAME"
	IpConfigEnvVar                = "CALICOVPP_IP_CONFIG"
	RxModeEnvVar                  = "CALICOVPP_RX_MODE"
	TapRxModeEnvVar               = "CALICOVPP_TAP_RX_MODE"
	InterfaceEnvVar               = "CALICOVPP_INTERFACE"
	ConfigTemplateEnvVar          = "CALICOVPP_CONFIG_TEMPLATE"
	ConfigExecTemplateEnvVar      = "CALICOVPP_CONFIG_EXEC_TEMPLATE"
	VppStartupSleepEnvVar         = "CALICOVPP_VPP_STARTUP_SLEEP"
	ExtraAddrCountEnvVar          = "CALICOVPP_CONFIGURE_EXTRA_ADDRESSES"
	CorePatternEnvVar             = "CALICOVPP_CORE_PATTERN"
	ServicePrefixEnvVar           = "SERVICE_PREFIX"
	HostIfName                    = "vpptap0"
	HostIfTag                     = "hosttap"
	VppTapIP4PrefixLen            = 30
	VppTapIP6PrefixLen            = 120
	VppSigKillTimeout             = 2
	vppSideMacAddressString       = "02:00:00:00:00:02"
	containerSideMacAddressString = "02:00:00:00:00:01"
	vppFakeNextHopIP4String       = "169.254.254.254"
	vppTapIP4String               = "169.254.254.253"
	vppFakeNextHopIP6String       = "fc00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	vppTapIP6String               = "fc00:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
)

var (
	runningCond   *sync.Cond
	initialConfig interfaceConfig
	params        vppManagerParams
	vpp           *vpplink.VppLink
	vppCmd        *exec.Cmd
	vppProcess    *os.Process
	vppDeadChan   chan bool
	vppAlive      bool
	signals       chan os.Signal
)

type interfaceConfig struct {
	pciId     string
	driver    string
	isUp      bool
	addresses []netlink.Addr
	routes    []netlink.Route
}

type vppManagerParams struct {
	vppStartupSleepSeconds  int
	hasv4                   bool
	hasv6                   bool
	nodeIP4                 string
	nodeIP6                 string
	mainInterface           string
	configExecTemplate      string
	configTemplate          string
	nodeName                string
	corePattern             string
	rxMode                  types.RxMode
	tapRxMode               types.RxMode
	serviceNet              *net.IPNet
	vppIpConfSource         string
	extraAddrCount          int
	vppSideMacAddress       net.HardwareAddr
	containerSideMacAddress net.HardwareAddr
	vppFakeNextHopIP4       net.IP
	vppTapIP4               net.IP
	vppFakeNextHopIP6       net.IP
	vppTapIP6               net.IP
}

func getRxMode(envVar string) types.RxMode {
	switch os.Getenv(envVar) {
	case "interrupt":
		return types.Interrupt
	case "polling":
		return types.Polling
	case "adaptive":
		return types.Adaptative
	default:
		return types.DefaultRxMode
	}
}

func parseEnvVariables() (err error) {
	vppStartupSleep := os.Getenv(VppStartupSleepEnvVar)
	if vppStartupSleep == "" {
		params.vppStartupSleepSeconds = 0
	} else {
		i, err := strconv.ParseInt(vppStartupSleep, 10, 32)
		params.vppStartupSleepSeconds = int(i)
		if err != nil {
			return errors.Wrapf(err, "Error Parsing %s", VppStartupSleepEnvVar)
		}
	}

	params.mainInterface = os.Getenv(InterfaceEnvVar)
	if params.mainInterface == "" {
		return errors.Errorf("No interface specified. Specify an interface through the %s environment variable", InterfaceEnvVar)
	}

	params.configExecTemplate = os.Getenv(ConfigExecTemplateEnvVar)

	params.configTemplate = os.Getenv(ConfigTemplateEnvVar)
	if params.configTemplate == "" {
		return fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}

	params.nodeName = os.Getenv(NodeNameEnvVar)
	if params.nodeName == "" {
		return errors.Errorf("No node name specified. Specify the NODENAME environment variable")
	}

	servicePrefixStr := os.Getenv(ServicePrefixEnvVar)
	_, params.serviceNet, err = net.ParseCIDR(servicePrefixStr)
	if err != nil {
		return errors.Errorf("invalid service prefix configuration: %s %s", servicePrefixStr, err)
	}

	params.vppIpConfSource = os.Getenv(IpConfigEnvVar)
	if params.vppIpConfSource != "linux" { // TODO add other sources
		return errors.Errorf("No ip configuration source specified. Specify one of linux, [[calico or dhcp]] through the %s environment variable", IpConfigEnvVar)
	}

	params.corePattern = os.Getenv(CorePatternEnvVar)

	params.extraAddrCount = 0
	if extraAddrConf := os.Getenv(ExtraAddrCountEnvVar); extraAddrConf != "" {
		extraAddrCount, err := strconv.ParseInt(extraAddrConf, 10, 8)
		if err != nil {
			log.Errorf("Couldn't parse %s: %v", ExtraAddrCountEnvVar, err)
		} else {
			params.extraAddrCount = int(extraAddrCount)
		}
	}

	params.rxMode = getRxMode(RxModeEnvVar)
	params.tapRxMode = getRxMode(TapRxModeEnvVar)

	params.vppSideMacAddress, err = net.ParseMAC(vppSideMacAddressString)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse mac: %s", vppSideMacAddressString)
	}
	params.containerSideMacAddress, err = net.ParseMAC(containerSideMacAddressString)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse mac: %s", containerSideMacAddressString)
	}
	params.vppFakeNextHopIP4 = net.ParseIP(vppFakeNextHopIP4String)
	if params.vppFakeNextHopIP4 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppFakeNextHopIP4String)
	}
	params.vppTapIP4 = net.ParseIP(vppTapIP4String)
	if params.vppTapIP4 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppTapIP4String)
	}
	params.vppFakeNextHopIP6 = net.ParseIP(vppFakeNextHopIP6String)
	if params.vppFakeNextHopIP6 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppFakeNextHopIP6String)
	}
	params.vppTapIP6 = net.ParseIP(vppTapIP6String)
	if params.vppTapIP6 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppTapIP6String)
	}
	return nil
}

func timeOutSigKill() {
	time.Sleep(VppSigKillTimeout * time.Second)
	log.Infof("Timeout : SIGKILL vpp")
	signals <- syscall.SIGKILL
}

func terminateVpp(format string, args ...interface{}) {
	log.Errorf(format, args...)
	log.Infof("Terminating Vpp (SIGINT)")
	signals <- syscall.SIGINT
}

func handleSignals() {
	signals = make(chan os.Signal, 10)
	signal.Notify(signals)
	signal.Reset(syscall.SIGURG)
	for {
		s := <-signals
		if vppProcess == nil && s == syscall.SIGCHLD {
			/* Don't handle sigchld before vpp starts
			   There might still be a race condition if
			   vpp sefaults right on startup */
			continue
		} else if vppProcess == nil {
			runningCond.L.Lock()
			for vppProcess == nil {
				runningCond.Wait()
			}
			runningCond.L.Unlock()
		}
		log.Infof("Received signal %+v", s)
		if s == syscall.SIGCHLD {
			processState, err := vppCmd.Process.Wait()
			vppDeadChan <- true
			if err != nil {
				log.Errorf("processWait errored with %v", err)
			} else {
				log.Infof("processWait returned %v", processState)
			}
		} else {
			/* special case
			   for SIGTERM, which doesn't kill vpp quick enough */
			if s == syscall.SIGTERM {
				s = syscall.SIGINT
			}
			vppProcess.Signal(s)
			log.Infof("Signaled vpp (PID %d) %+v", vppProcess.Pid, s)
			if s == syscall.SIGINT || s == syscall.SIGQUIT || s == syscall.SIGSTOP {
				go timeOutSigKill()
			}
		}
		log.Infof("Done with signal %+v", s)
	}
}

func getNodeAddress(isV6 bool) string {
	for _, addr := range initialConfig.addresses {
		if vpplink.IsIP6(addr.IP) == isV6 {
			return addr.IPNet.String()
		}
	}
	return ""
}

func getLinuxConfig() error {
	link, err := netlink.LinkByName(params.mainInterface)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", params.mainInterface)
	}
	initialConfig.isUp = (link.Attrs().Flags & net.FlagUp) != 0
	if initialConfig.isUp {
		// Grab addresses and routes
		initialConfig.addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s addresses", params.mainInterface)
		}
		initialConfig.routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s routes", params.mainInterface)
		}
	}
	params.nodeIP4 = getNodeAddress(false)
	params.nodeIP6 = getNodeAddress(true)
	params.hasv4 = (params.nodeIP4 != "")
	params.hasv6 = (params.nodeIP6 != "")
	if !params.hasv4 && !params.hasv6 {
		return errors.Errorf("no address found for node")
	}
	log.Infof("Node IP4 %s , Node IP6 %s", params.nodeIP4, params.nodeIP6)

	// We allow PCI not to be found e.g for AF_PACKET
	// Grab PCI id
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", params.mainInterface)
	devicePath, err := os.Readlink(deviceLinkPath)
	if err != nil {
		log.Warnf("cannot find pci device for %s : %s", params.mainInterface, err)
		return nil
	}
	initialConfig.pciId = strings.TrimLeft(devicePath, "./")
	// Grab Driver id
	driverLinkPath := fmt.Sprintf("/sys/class/net/%s/device/driver", params.mainInterface)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		log.Warnf("cannot find driver for %s : %s", params.mainInterface, err)
		return nil
	}
	initialConfig.driver = driverPath[strings.LastIndex(driverPath, "/")+1:]
	log.Infof("Initial device config: %+v", initialConfig)
	return nil
}

func isDriverLoaded(driver string) (bool, error) {
	_, err := os.Stat("/sys/bus/pci/drivers/" + driver)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func checkDrivers() {
	vfioLoaded, err := isDriverLoaded("vfio-pci")
	if err != nil {
		log.Warnf("error determining whether vfio-pci is loaded")
	}
	uioLoaded, err := isDriverLoaded("uio_pci_generic")
	if err != nil {
		log.Warnf("error determining whether vfio-pci is loaded")
	}
	if !vfioLoaded && !uioLoaded {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
}

func swapDriver(pciDevice, newDriver string) error {
	unbindPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver/unbind", pciDevice)
	err := ioutil.WriteFile(unbindPath, []byte(pciDevice), 0200)
	if err != nil {
		return errors.Wrapf(err, "error unbinding %s", pciDevice)
	}
	bindPath := fmt.Sprintf("/sys/bus/pci/drivers/%s/bind", newDriver)
	err = ioutil.WriteFile(bindPath, []byte(pciDevice), 0200)
	if err != nil {
		return errors.Wrapf(err, "error binding %s to %s", pciDevice, newDriver)
	}
	return nil
}

func writeFile(state string, path string) error {
	err := ioutil.WriteFile(path, []byte(state+"\n"), 0400)
	if err != nil {
		return errors.Errorf("Failed to write state to %s", path)
	}
	return nil
}

func restoreLinuxConfig() (err error) {
	// No need to delete the tap we created with VPP since it should disappear with all its configuration
	// when VPP dies
	if initialConfig.pciId != "" && initialConfig.driver != "" {
		err := swapDriver(initialConfig.pciId, initialConfig.driver)
		if err != nil {
			return errors.Wrapf(err, "error swapping back driver to %s for %s", initialConfig.driver, initialConfig.pciId)
		}
	}
	if initialConfig.isUp {
		// This assumes the link has kept the same name after the rebind.
		// It should be always true on systemd based distros
		retries := 0
		var link netlink.Link
		for {
			link, err = netlink.LinkByName(params.mainInterface)
			if err != nil {
				retries += 1
				if retries >= 10 {
					return errors.Wrapf(err, "error finding link %s after %d tries", params.mainInterface, retries)
				}
				time.Sleep(500 * time.Millisecond)
			} else {
				log.Infof("found links %s after %d tries", params.mainInterface, retries)
				break
			}
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			return errors.Wrapf(err, "error setting link %s back up", params.mainInterface)
		}
		// Re-add all adresses and routes
		failed := false
		for _, addr := range initialConfig.addresses {
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
		for _, route := range initialConfig.routes {
			if route.Dst != nil && vpplink.IsIP6(route.Dst.IP) && route.Dst.IP.IsLinkLocalUnicast() {
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
	}
	return nil
}

func generateVppConfigExecFile() error {
	if params.configExecTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.configExecTemplate, "__VPP_DATAPLANE_IF__", params.mainInterface)
	err := errors.Wrapf(
		ioutil.WriteFile(VppConfigExecFile, []byte(template+"\n"), 0744),
		"error writing VPP Exec configuration to %s",
		VppConfigFile,
	)
	if err != nil {
		return err
	}
	if strings.HasPrefix(params.configExecTemplate, "#!/bin/bash") {
		cmd := exec.Command("/bin/bash", VppConfigExecFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
	}
	return err
}

func generateVppConfigFile() error {
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.configTemplate, "__PCI_DEVICE_ID__", initialConfig.pciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", params.mainInterface)
	return errors.Wrapf(
		ioutil.WriteFile(VppConfigFile, []byte(template+"\n"), 0644),
		"error writing VPP configuration to %s",
		VppConfigFile,
	)
}

func removeInitialRoutes(link netlink.Link) {
	for _, route := range initialConfig.routes {
		log.Infof("deleting Route %s", route.String())
		err := netlink.RouteDel(&route)
		if err != nil {
			log.Errorf("cannot delete route %+v: %+v", route, err)
			// Keep going for the rest of the config
		}
	}
	for _, addr := range initialConfig.addresses {
		err := netlink.AddrDel(link, &addr)
		if err != nil {
			log.Errorf("error adding address %s to tap interface : %+v", addr, err)
		}
	}
}

func configurePunt(tapSwIfIndex uint32) (err error) {
	if params.hasv4 {
		log.Infof("Configuring ip4 punt")
		err := vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, params.vppFakeNextHopIP4)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 punt")
		}
	}
	if params.hasv6 {
		log.Infof("Configuring ip6 punt")
		err := vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, params.vppFakeNextHopIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv6 punt")
		}
	}
	return nil
}

func configureLinuxTap(link netlink.Link) (err error) {
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "error setting tap %s up", HostIfName)
	}
	// Add /32 or /128 for each address configured on VPP side
	for _, addr := range initialConfig.addresses {
		singleAddr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   addr.IP,
				Mask: getMaxCIDRMask(addr.IP),
			},
			Label: HostIfName,
		}
		log.Infof("Adding address %+v to tap interface", singleAddr)
		err = netlink.AddrAdd(link, &singleAddr)
		if err != nil {
			return errors.Wrapf(err, "error adding address %s to tap interface", singleAddr)
		}
	}
	return nil
}

func getMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func getMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func safeAddInterfaceAddress(swIfIndex uint32, addr *net.IPNet) (err error) {
	maskSize, _ := addr.Mask.Size()
	if vpplink.IsIP6(addr.IP) && maskSize != 128 {
		err = vpp.AddInterfaceAddress(swIfIndex, &net.IPNet{
			IP:   addr.IP,
			Mask: getMaxCIDRMask(addr.IP),
		})
		if err != nil {
			return err
		}
		log.Infof("Adding extra route to %s for %d mask", addr, maskSize)
		return vpp.RouteAdd(&types.Route{
			Dst: addr,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		})
	}
	return vpp.AddInterfaceAddress(swIfIndex, addr)
}

func configureVppTap(link netlink.Link, tapSwIfIndex uint32, tapAddr net.IP, nxtHop net.IP, prefixLen int) (err error) {
	// Do the actual VPP and Linux configuration
	addr := &net.IPNet{
		IP:   tapAddr,
		Mask: getMaxCIDRMask(tapAddr),
	}
	err = safeAddInterfaceAddress(tapSwIfIndex, addr)
	if err != nil {
		return errors.Wrap(err, "error adding address to tap")
	}
	err = vpp.AddNeighbor(&types.Neighbor{
		SwIfIndex:    tapSwIfIndex,
		IP:           nxtHop,
		HardwareAddr: params.containerSideMacAddress,
	})
	if err != nil {
		return errors.Wrap(err, "error adding neighbor to tap")
	}

	// "dummy" next-hop directly connected on the tap interface (route + neighbor)
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   tapAddr,
			Mask: getMaxCIDRMask(tapAddr),
		},
		Scope: netlink.SCOPE_LINK,
	})
	if err != nil {
		return errors.Wrap(err, "cannot add connected route to tap")
	}
	err = netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           tapAddr,
		HardwareAddr: params.vppSideMacAddress[:],
	})
	if err != nil {
		return errors.Wrap(err, "cannot add neighbor to tap")
	}
	if vpplink.IsIP4(params.serviceNet.IP) == vpplink.IsIP4(tapAddr) {
		// Add a route for the service prefix through VPP
		log.Infof("adding route to service prefix %s through VPP", params.serviceNet.String())
		err = netlink.RouteAdd(&netlink.Route{
			Dst:       params.serviceNet,
			LinkIndex: link.Attrs().Index,
			Gw:        tapAddr,
		})
		if err != nil {
			return errors.Wrap(err, "cannot add service route to tap")
		}
	}

	// All routes that were on this interface now go through VPP
	for _, route := range initialConfig.routes {
		if route.Dst == nil || vpplink.IsIP4(route.Dst.IP) != vpplink.IsIP4(tapAddr) {
			continue
		}
		newRoute := netlink.Route{
			Dst:       route.Dst,
			LinkIndex: link.Attrs().Index,
			Gw:        tapAddr,
		}
		log.Infof("Adding route %+v via VPP", newRoute)
		err = netlink.RouteAdd(&newRoute)
		if err == syscall.EEXIST {
			log.Warnf("cannot add route %+v via vpp, %+v", newRoute, err)
		} else if err != nil {
			return errors.Wrapf(err, "cannot add route %+v via vpp", newRoute)
		}
	}
	return nil
}

func createVppLink() (vpp *vpplink.VppLink, err error) {
	// Get an API connection, with a few retries to accomodate VPP startup time
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(VppApiSocket, log.WithFields(log.Fields{"component": "vpp-api"}))
		if err != nil {
			log.Warnf("Cannot connect to VPP on socket %s try %d/10: %v", VppApiSocket, i, err)
			err = nil
			time.Sleep(2 * time.Second)
		} else {
			return vpp, nil
		}
	}
	return nil, errors.Errorf("Cannot connect to VPP after 10 tries")
}

func addExtraAddresses(addrList []netlink.Addr) (err error) {
	log.Infof("Adding %d extra addresses", params.extraAddrCount)
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
	for i := 1; i <= params.extraAddrCount; i++ {
		a := &net.IPNet{
			IP:   net.IP(append([]byte(nil), addr.IP.To4()...)),
			Mask: addr.Mask,
		}
		a.IP[2] += byte(i)
		err = safeAddInterfaceAddress(DataInterfaceSwIfIndex, a)
		if err != nil {
			log.Errorf("error adding address to data interface: %v", err)
		}
	}
	return nil
}

func configureVpp(vpp *vpplink.VppLink) (err error) {
	defer vpp.Close()
	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	err = vpp.EnableGSOFeature(DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error enabling GSO on data interface")
	}

	err = vpp.SetInterfaceRxMode(DataInterfaceSwIfIndex, types.AllQueues, params.rxMode)
	if err != nil {
		log.Errorf("error SetInterfaceRxMode on data interface %v", err)
	}

	err = vpp.EnableInterfaceIP6(DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error enabling ip6 on if")
	}

	for _, addr := range initialConfig.addresses {
		log.Infof("Adding address %s to data interface", addr.String())
		err = safeAddInterfaceAddress(DataInterfaceSwIfIndex, addr.IPNet)
		if err != nil {
			log.Errorf("error adding address to data interface: %v", err)
		}
	}
	for _, route := range initialConfig.routes {
		// Only add routes with a next hop, assume the others come from interface addresses
		if route.Gw == nil || route.Dst == nil {
			continue
		}
		err = vpp.RouteAdd(&types.Route{
			Dst: route.Dst,
			Paths: []types.RoutePath{{
				Gw:        route.Gw,
				SwIfIndex: DataInterfaceSwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("cannot add route in vpp: %v", err)
		}
	}
	err = addExtraAddresses(initialConfig.addresses)
	if err != nil {
		log.Errorf("Cannot configure requested extra addresses: %v", err)
	}
	err = vpp.SetIPFlowHash(0, false, true, true, true, true, false, false, true)
	if err != nil {
		log.Errorf("cannot configure flow hash: %v", err)
	}
	err = vpp.SetIPFlowHash(0, true, true, true, true, true, false, false, true)
	if err != nil {
		log.Errorf("cannot configure flow hash: %v", err)
	}

	// If main interface is still up flush its routes or they'll conflict with $HostIfName
	link, err := netlink.LinkByName(params.mainInterface)
	if err == nil {
		isUp := (link.Attrs().Flags & net.FlagUp) != 0
		if isUp {
			removeInitialRoutes(link)
		}
	}

	log.Infof("Creating Linux side interface")
	tapSwIfIndex, err := vpp.CreateTapV2(&types.TapV2{
		HostIfName:     HostIfName,
		Tag:            HostIfTag,
		MacAddress:     params.vppSideMacAddress,
		HostMacAddress: params.containerSideMacAddress,
	})
	if err != nil {
		return errors.Wrap(err, "error creating tap")
	}
	err = writeFile(strconv.FormatInt(int64(tapSwIfIndex), 10), VppManagerTapIdxFile)
	if err != nil {
		return errors.Wrap(err, "error writing tap idx")
	}

	err = vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting tap up")
	}

	err = vpp.EnableInterfaceIP6(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error enabling ip6 on vpptap0")
	}

	err = vpp.SetInterfaceRxMode(tapSwIfIndex, types.AllQueues, params.tapRxMode)
	if err != nil {
		log.Errorf("error SetInterfaceRxMode on vpptap0 %v", err)
	}

	err = configurePunt(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error adding redirect to tap")
	}

	// Linux side tap setup
	link, err = netlink.LinkByName(HostIfName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", HostIfName)
	}

	err = configureLinuxTap(link)
	if err != nil {
		return errors.Wrap(err, "error configure tap linux side")
	}

	err = configureVppTap(link, tapSwIfIndex, params.vppTapIP4, params.vppFakeNextHopIP4, VppTapIP4PrefixLen)
	if err != nil {
		return errors.Wrap(err, "error configuring vpp side ipv4 tap")
	}

	err = configureVppTap(link, tapSwIfIndex, params.vppTapIP6, params.vppFakeNextHopIP6, VppTapIP6PrefixLen)
	if err != nil {
		return errors.Wrap(err, "error configuring vpp side ipv6 tap")
	}

	// TODO should watch for service prefix and ip pools to always route them through VPP
	// Service prefix is needed even if kube-proxy is running on the host to ensure correct source address selection
	return nil
}

func updateCalicoNode() (err error) {
	var node *calicoapi.Node
	client, err := calicocli.NewFromEnv()
	if err != nil {
		return errors.Wrap(err, "error creating calico client")
	}
	// TODO create if doesn't exist? need to be careful to do it atomically... and everyone else must as well.
	for i := 0; i < 10; i++ {
		node, err = client.Nodes().Get(context.Background(), params.nodeName, calicoopts.GetOptions{})
		if err == nil {
			break
		}
		log.Warnf("Try [%d] cannot get current node from Calico %+v", i, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return errors.Wrap(err, "cannot get current node from Calico")
	}

	// Update node with address
	if node.Spec.BGP == nil {
		node.Spec.BGP = &calicoapi.NodeBGPSpec{}
	}
	if params.hasv4 {
		log.Infof("Setting BGP V4 conf %s", params.nodeIP4)
		node.Spec.BGP.IPv4Address = params.nodeIP4
	}
	if params.hasv6 {
		log.Infof("Setting BGP V6 conf %s", params.nodeIP6)
		node.Spec.BGP.IPv6Address = params.nodeIP6
	}
	log.Debugf("updating node with: %+v", node)
	updated, err := client.Nodes().Update(context.Background(), node, calicoopts.SetOptions{})
	// TODO handle update error / retry if object changed in the meantime
	log.Debugf("updated node: %+v", updated)
	return errors.Wrapf(err, "error updating node %s", params.nodeName)
}

func pingCalicoVpp() error {
	dat, err := ioutil.ReadFile(CalicoVppPidFile)
	if err != nil {
		return errors.Wrapf(err, "Error reading %s", CalicoVppPidFile)
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
func runVpp() (err error) {
	if initialConfig.isUp {
		// Set interface down if it is up, bind it to a VPP-friendly driver
		link, err := netlink.LinkByName(params.mainInterface)
		if err != nil {
			return errors.Wrapf(err, "error finding link %s", params.mainInterface)
		}
		err = netlink.LinkSetDown(link)
		if err != nil {
			// In case it still succeeded
			netlink.LinkSetUp(link)
			return errors.Wrapf(err, "error setting link %s down", params.mainInterface)
		}
	}
	// From this point it is very important that every exit path calls restoreLinuxConfig after vpp exits
	vppCmd = exec.Command(VppPath, "-c", VppConfigFile)
	vppCmd.Stdout = os.Stdout
	vppCmd.Stderr = os.Stderr
	err = vppCmd.Start()
	if err != nil {
		restoreConfiguration()
		return errors.Wrap(err, "error starting vpp process")
	}
	vppProcess = vppCmd.Process
	log.Infof("VPP started. PID: %d", vppProcess.Pid)
	runningCond.Broadcast()

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(params.vppStartupSleepSeconds) * time.Second)

	vpp, err = createVppLink()
	if err != nil {
		terminateVpp("Error connecting to VPP (SIGINT %d): %v", vppProcess.Pid, err)
		restoreConfiguration()
		vpp.Close()
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}

	// Data interface configuration
	err = vpp.Retry(2*time.Second, 10, vpp.InterfaceAdminUp, DataInterfaceSwIfIndex)
	if err != nil {
		terminateVpp("Error setting main interface up (SIGINT %d): %v", vppProcess.Pid, err)
		restoreConfiguration()
		vpp.Close()
		return errors.Wrap(err, "error setting data interface up")
	}

	// Configure VPP
	err = configureVpp(vpp)
	if err != nil {
		terminateVpp("Error configuring VPP (SIGINT %d): %v", vppProcess.Pid, err)
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = updateCalicoNode()
	if err != nil {
		terminateVpp("Error updating Calico node (SIGINT %d): %v", vppProcess.Pid, err)
	}

	go syncPools()

	writeFile("1", VppManagerStatusFile)
	<-vppDeadChan
	log.Infof("VPP Exited: status %v", err)
	restoreConfiguration()
	return nil
}

func restoreConfiguration() {
	log.Infof("Restoring configuration")
	err := clearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing vpp manager files: %v", err)
	}
	err = restoreLinuxConfig()
	if err != nil {
		log.Errorf("Error restoring linux config: %v", err)
	}
	err = pingCalicoVpp()
	if err != nil {
		log.Errorf("Error pinging calico-vpp: %v", err)
	}
}

func configureContainer() error {
	lim := syscall.Rlimit{
		Cur: ^uint64(0),
		Max: ^uint64(0),
	}
	err := syscall.Setrlimit(8, &lim) // 8 - RLIMIT_MEMLOCK
	return errors.Wrap(err, "Error raising memlock limit, VPP may fail to start")
}

func clearVppManagerFiles() error {
	err := writeFile("0", VppManagerStatusFile)
	if err != nil {
		return err
	}
	return writeFile("-1", VppManagerTapIdxFile)
}

func setCorePattern() {
	if params.corePattern == "" {
		return
	}
	log.Infof("Setting corePattern to : %s", params.corePattern)
	err := writeFile(params.corePattern, "/proc/sys/kernel/core_pattern")
	if err != nil {
		log.Errorf("Error writing corePattern: %+v", err)
	}
}

func main() {
	vppDeadChan = make(chan bool, 1)
	vppAlive = false

	/* Run this first in case this is a script
	 * that's responsible for creating a VF */
	err := generateVppConfigExecFile()
	if err != nil {
		log.Errorf("Error generating VPP config Exec: %s", err)
		return
	}

	err = clearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing config files: %+v", err)
		return
	}
	err = parseEnvVariables()
	if err != nil {
		log.Errorf("Error parsing env varibales: %+v", err)
		return
	}
	setCorePattern()

	err = configureContainer()
	if err != nil {
		log.Errorf("Error during initial config:")
	}

	checkDrivers()

	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()

	err = getLinuxConfig()
	if err != nil {
		log.Errorf("Error getting initial interface configuration: %s", err)
		return
	}

	err = generateVppConfigFile()
	if err != nil {
		log.Errorf("Error generating VPP config: %s", err)
		return
	}
	err = runVpp()
	if err != nil {
		log.Errorf("Error running VPP: %v", err)
	}
	return
}
