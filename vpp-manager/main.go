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

	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoopts "github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	NumRxQueuesEnvVar             = "CALICOVPP_RX_QUEUES"
	TapRxModeEnvVar               = "CALICOVPP_TAP_RX_MODE"
	InterfaceEnvVar               = "CALICOVPP_INTERFACE"
	ConfigTemplateEnvVar          = "CALICOVPP_CONFIG_TEMPLATE"
	ConfigExecTemplateEnvVar      = "CALICOVPP_CONFIG_EXEC_TEMPLATE"
	InitScriptTemplateEnvVar      = "CALICOVPP_INIT_SCRIPT_TEMPLATE"
	IfConfigPathEnvVar            = "CALICOVPP_IF_CONFIG_PATH"
	VppStartupSleepEnvVar         = "CALICOVPP_VPP_STARTUP_SLEEP"
	ExtraAddrCountEnvVar          = "CALICOVPP_CONFIGURE_EXTRA_ADDRESSES"
	CorePatternEnvVar             = "CALICOVPP_CORE_PATTERN"
	TapRingSizeEnvVar             = "CALICOVPP_TAP_RING_SIZE"
	RingSizeEnvVar                = "CALICOVPP_RING_SIZE"
	NativeDriverEnvVar            = "CALICOVPP_NATIVE_DRIVER"
	SwapDriverEnvVar              = "CALICOVPP_SWAP_DRIVER"
	DefaultGWEnvVar               = "CALICOVPP_DEFAULT_GW"
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
	defaultRxMode                 = types.Adaptative
)

const (
	NATIVE_DRIVER_NONE      = "none"
	NATIVE_DRIVER_AF_PACKET = "af_packet"
	NATIVE_DRIVER_AF_XDP    = "af_xdp"
)

var (
	runningCond   *sync.Cond
	initialConfig *interfaceConfig
	params        vppManagerParams
	vpp           *vpplink.VppLink
	vppCmd        *exec.Cmd
	vppProcess    *os.Process
	vppDeadChan   chan bool
	vppAlive      bool
	signals       chan os.Signal
)

func ServiceCIDRsString() string {
	var str []string
	for _, cidr := range params.serviceCIDRs {
		str = append(str, cidr.String())
	}
	return strings.Join(str, ",")
}

type vppManagerParams struct {
	vppStartupSleepSeconds  int
	mainInterface           string
	configExecTemplate      string
	configTemplate          string
	initScriptTemplate      string
	nodeName                string
	corePattern             string
	rxMode                  types.RxMode
	tapRxMode               types.RxMode
	serviceCIDRs            []*net.IPNet
	vppIpConfSource         string
	extraAddrCount          int
	vppSideMacAddress       net.HardwareAddr
	containerSideMacAddress net.HardwareAddr
	vppFakeNextHopIP4       net.IP
	vppTapIP4               net.IP
	vppFakeNextHopIP6       net.IP
	vppTapIP6               net.IP
	nativeDriver            string
	TapRxQueueSize          int
	TapTxQueueSize          int
	RxQueueSize             int
	TxQueueSize             int
	NumRxQueues             int
	newDriverName           string
	defaultGWs              []net.IP
	ifConfigSavePath        string
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
		return defaultRxMode
	}
}

func formatRxMode(rxMode types.RxMode) string {
	switch rxMode {
	case types.Interrupt:
		return "interrupt"
	case types.Polling:
		return "polling"
	case types.Adaptative:
		return "adaptive"
	default:
		return "default"
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
	params.initScriptTemplate = os.Getenv(InitScriptTemplateEnvVar)

	params.configTemplate = os.Getenv(ConfigTemplateEnvVar)
	if params.configTemplate == "" {
		return fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}

	params.ifConfigSavePath = os.Getenv(IfConfigPathEnvVar)

	params.nodeName = os.Getenv(NodeNameEnvVar)
	if params.nodeName == "" {
		return errors.Errorf("No node name specified. Specify the NODENAME environment variable")
	}

	servicePrefixStr := os.Getenv(ServicePrefixEnvVar)
	for _, prefixStr := range strings.Split(servicePrefixStr, ",") {
		_, serviceCIDR, err := net.ParseCIDR(prefixStr)
		if err != nil {
			return errors.Errorf("invalid service prefix configuration: %s %s", prefixStr, err)
		}
		params.serviceCIDRs = append(params.serviceCIDRs, serviceCIDR)
	}

	params.vppIpConfSource = os.Getenv(IpConfigEnvVar)
	if params.vppIpConfSource != "linux" { // TODO add dhcp, config file, etc.
		return errors.Errorf("No ip configuration source specified. Specify one of {linux,} through the %s environment variable", IpConfigEnvVar)
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

	params.nativeDriver = NATIVE_DRIVER_NONE
	if conf := os.Getenv(NativeDriverEnvVar); conf != "" {
		params.nativeDriver = conf
	}

	if conf := os.Getenv(NumRxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", NumRxQueuesEnvVar, conf, queues, err)
		}
		params.NumRxQueues = int(queues)
	}

	params.newDriverName = os.Getenv(SwapDriverEnvVar)

	params.rxMode = getRxMode(RxModeEnvVar)
	params.tapRxMode = getRxMode(TapRxModeEnvVar)

	params.vppTapIP4 = net.ParseIP(vppTapIP4String)
	if params.vppTapIP4 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppTapIP4String)
	}
	params.vppTapIP6 = net.ParseIP(vppTapIP6String)
	if params.vppTapIP6 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppTapIP6String)
	}
	if conf := os.Getenv(DefaultGWEnvVar); conf != "" {
		for _, defaultGWStr := range strings.Split(conf, ",") {
			defaultGW := net.ParseIP(defaultGWStr)
			if defaultGW == nil {
				return errors.Errorf("Unable to parse IP: %s", conf)
			}
			params.defaultGWs = append(params.defaultGWs, defaultGW)
		}
	}
	params.TapRxQueueSize, params.TapTxQueueSize, err = parseRingSize(TapRingSizeEnvVar)
	if err != nil {
		return err
	}
	params.RxQueueSize, params.TxQueueSize, err = parseRingSize(RingSizeEnvVar)
	if err != nil {
		return err
	}
	return nil
}

func parseRingSize(envVar string) (int, int, error) {
	rxSize := 0
	txSize := 0
	if conf := os.Getenv(envVar); conf != "" {
		sizes := strings.Split(conf, ",")
		if len(sizes) == 1 {
			sz, err := strconv.ParseInt(sizes[0], 10, 32)
			if err != nil {
				return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", envVar, conf, sz, err)
			}
			rxSize = int(sz)
			txSize = int(sz)
		} else if len(sizes) == 2 {
			sz, err := strconv.ParseInt(sizes[0], 10, 32)
			if err != nil {
				return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", envVar, conf, sz, err)
			}
			rxSize = int(sz)
			sz, err = strconv.ParseInt(sizes[1], 10, 32)
			if err != nil {
				return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", envVar, conf, sz, err)
			}
			txSize = int(sz)
		} else {
			return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v", envVar, conf, sizes)
		}
	}
	return rxSize, txSize, nil
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
		log.Warnf("Error determining whether vfio-pci is loaded")
	}
	uioLoaded, err := isDriverLoaded("uio_pci_generic")
	if err != nil {
		log.Warnf("Error determining whether vfio-pci is loaded")
	}
	if !vfioLoaded && !uioLoaded {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
}

func swapDriver(pciDevice, newDriver string, addId bool) error {
	deviceRoot := fmt.Sprintf("/sys/bus/pci/devices/%s", pciDevice)
	driverRoot := fmt.Sprintf("/sys/bus/pci/drivers/%s", newDriver)
	if addId {
		// Grab device vendor and id
		vendor, err := ioutil.ReadFile(deviceRoot + "/vendor")
		if err != nil {
			return errors.Wrapf(err, "Error reading device %s vendor", pciDevice)
		}
		device, err := ioutil.ReadFile(deviceRoot + "/device")
		if err != nil {
			return errors.Wrapf(err, "Error reading device %s id", pciDevice)
		}
		// Add it to driver before unbinding to prevent spontaneous binds
		identifier := fmt.Sprintf("%s %s\n", string(vendor[2:6]), string(device[2:6]))
		log.Infof("Adding id '%s' to driver %s", identifier, newDriver)
		err = ioutil.WriteFile(driverRoot+"/new_id", []byte(identifier), 0200)
		if err != nil {
			log.Warnf("Could not add id %s to driver %s: %v", identifier, newDriver, err)
		}
	}
	err := ioutil.WriteFile(deviceRoot+"/driver/unbind", []byte(pciDevice), 0200)
	if err != nil {
		// Error on unbind is not critical, device might beind successfully afterwards if it is not currently bound
		log.Warnf("Error unbinding %s: %v", pciDevice, err)
	}
	err = ioutil.WriteFile(driverRoot+"/bind", []byte(pciDevice), 0200)
	return errors.Wrapf(err, "Error binding %s to %s", pciDevice, newDriver)
}

func writeFile(state string, path string) error {
	err := ioutil.WriteFile(path, []byte(state+"\n"), 0400)
	if err != nil {
		return errors.Errorf("Failed to write state to %s", path)
	}
	return nil
}

func routeIsIP6(r *netlink.Route) bool {
	if r.Dst != nil {
		return vpplink.IsIP6(r.Dst.IP)
	}
	if r.Gw != nil {
		return vpplink.IsIP6(r.Gw)
	}
	if r.Src != nil {
		return vpplink.IsIP6(r.Src)
	}
	return false
}

func routeIsLinkLocalUnicast(r *netlink.Route) bool {
	if r.Dst == nil {
		return false
	}
	if !vpplink.IsIP6(r.Dst.IP) {
		return false
	}
	return r.Dst.IP.IsLinkLocalUnicast()
}

func restoreLinuxConfig() (err error) {
	// No need to delete the tap we created with VPP since it should disappear with all its configuration
	// when VPP dies
	if initialConfig.PciId != "" && initialConfig.Driver != "" {
		err := swapDriver(initialConfig.PciId, initialConfig.Driver, false)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", initialConfig.Driver, initialConfig.PciId, err)
		}
	}
	if !initialConfig.IsUp {
		return nil
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	retries := 0
	failed := false
	var link netlink.Link
	for {
		link, err = netlink.LinkByName(params.mainInterface)
		if err != nil {
			retries += 1
			if retries >= 10 {
				return errors.Wrapf(err, "Error finding link %s after %d tries", params.mainInterface, retries)
			}
			time.Sleep(500 * time.Millisecond)
		} else {
			log.Infof("found links %s after %d tries", params.mainInterface, retries)
			break
		}
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s back up", params.mainInterface)
	}
	/* Restore XDP specific settings */
	if params.nativeDriver == NATIVE_DRIVER_AF_XDP {
		log.Infof("Removing AF XDP conf")
		if !initialConfig.PromiscOn {
			log.Infof("Setting promisc off")
			err = netlink.SetPromiscOff(link)
			if err != nil {
				log.Errorf("Error setting link %s promisc off %v", params.mainInterface, err)
				failed = true
			}
		}
		if initialConfig.NumRxQueues != params.NumRxQueues {
			log.Infof("Setting back %d queues", initialConfig.NumRxQueues)
			err = setInterfaceRxQueues(params.mainInterface, initialConfig.NumRxQueues)
			if err != nil {
				log.Errorf("Error setting link %s NumQueues to %d %v", params.mainInterface, initialConfig.NumRxQueues, err)
				failed = true
			}
		}
	}
	// Re-add all adresses and routes
	for _, addr := range initialConfig.Addresses {
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
	for _, route := range initialConfig.Routes {
		if routeIsLinkLocalUnicast(&route) {
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

func runInitScript() error {
	if params.initScriptTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.initScriptTemplate, "__VPP_DATAPLANE_IF__", params.mainInterface)
	cmd := exec.Command("/bin/bash", "-c", template)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func generateVppConfigExecFile() error {
	if params.configExecTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.configExecTemplate, "__PCI_DEVICE_ID__", initialConfig.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", params.mainInterface)
	err := errors.Wrapf(
		ioutil.WriteFile(VppConfigExecFile, []byte(template+"\n"), 0744),
		"Error writing VPP Exec configuration to %s",
		VppConfigExecFile,
	)
	return err
}

func generateVppConfigFile() error {
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.configTemplate, "__PCI_DEVICE_ID__", initialConfig.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", params.mainInterface)
	return errors.Wrapf(
		ioutil.WriteFile(VppConfigFile, []byte(template+"\n"), 0644),
		"Error writing VPP configuration to %s",
		VppConfigFile,
	)
}

func removeInitialRoutes(link netlink.Link) {
	for _, route := range initialConfig.Routes {
		log.Infof("deleting Route %s", route.String())
		err := netlink.RouteDel(&route)
		if err != nil {
			log.Errorf("cannot delete route %+v: %+v", route, err)
			// Keep going for the rest of the config
		}
	}
	for _, addr := range initialConfig.Addresses {
		err := netlink.AddrDel(link, &addr)
		if err != nil {
			log.Errorf("Error adding address %s to tap interface : %+v", addr, err)
		}
	}
}

func configurePunt(tapSwIfIndex uint32) (err error) {
	if initialConfig.Hasv4 {
		err := vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, net.ParseIP("0.0.0.0"))
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 punt")
		}
		err = vpp.PuntAllL4(false)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv4 L4 punt")
		}
	}
	if initialConfig.Hasv6 {
		err := vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, net.ParseIP("::"))
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv6 punt")
		}
		err = vpp.PuntAllL4(true)
		if err != nil {
			return errors.Wrapf(err, "Error configuring ipv6 L4 punt")
		}
	}
	return nil
}

func configureLinuxTap(link netlink.Link) (err error) {
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting tap %s up", HostIfName)
	}
	// Add /32 or /128 for each address configured on VPP side
	for _, addr := range initialConfig.Addresses {
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
			return errors.Wrapf(err, "Error adding address %s to tap interface", singleAddr)
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
	if vpplink.IsIP6(addr.IP) && maskSize != 128 && addr.IP.IsLinkLocalUnicast() {
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

func configureLinuxTapRoutes(link netlink.Link) (err error) {
	// All routes that were on this interface now go through VPP
	for _, route := range initialConfig.Routes {
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

	for _, serviceCIDR := range params.serviceCIDRs {
		// Add a route for the service prefix through VPP
		log.Infof("Adding route to service prefix %s through VPP", serviceCIDR.String())
		err = netlink.RouteAdd(&netlink.Route{
			Dst:       serviceCIDR,
			LinkIndex: link.Attrs().Index,
		})
		if err != nil {
			return errors.Wrapf(err, "cannot add tun route to service %s", serviceCIDR.String())
		}
	}
	return nil
}

func createVppLink() (vpp *vpplink.VppLink, err error) {
	// Get an API connection, with a few retries to accomodate VPP startup time
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(VppApiSocket, log.WithFields(log.Fields{"component": "vpp-api"}))
		if err != nil {
			log.Warnf("Try [%d/10] %v", i, err)
			err = nil
			time.Sleep(2 * time.Second)
		} else {
			return vpp, nil
		}
	}
	return nil, errors.Errorf("Cannot connect to VPP after 10 tries")
}

func addExtraAddresses(addrList []netlink.Addr) (err error) {
	if params.extraAddrCount == 0 {
		return nil
	}
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
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	return nil
}

func configureVpp(vpp *vpplink.VppLink) (err error) {
	// Always enable GSO feature on data interface, only a tiny negative effect on perf if GSO is not
	// enabled on the taps or already done before an encap
	err = vpp.EnableGSOFeature(DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling GSO on data interface")
	}

	err = vpp.SetInterfaceRxMode(DataInterfaceSwIfIndex, types.AllQueues, params.rxMode)
	if err != nil {
		log.Warnf("%v", err)
	}

	err = vpp.EnableInterfaceIP6(DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error enabling ip6 on if")
	}

	for _, addr := range initialConfig.Addresses {
		log.Infof("Adding address %s to data interface", addr.String())
		err = safeAddInterfaceAddress(DataInterfaceSwIfIndex, addr.IPNet)
		if err != nil {
			log.Errorf("Error adding address to data interface: %v", err)
		}
	}
	for _, route := range initialConfig.Routes {
		// Only add routes with a next hop, assume the others come from interface addresses
		if routeIsLinkLocalUnicast(&route) {
			log.Infof("Skipping linklocal route %s", route.String())
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
	for _, defaultGW := range params.defaultGWs {
		log.Infof("Adding default route to %s", defaultGW.String())
		err = vpp.RouteAdd(&types.Route{
			Paths: []types.RoutePath{{
				Gw:        defaultGW,
				SwIfIndex: DataInterfaceSwIfIndex,
			}},
		})
		if err != nil {
			log.Errorf("cannot add default route via %s in vpp: %v", defaultGW, err)
		}
	}
	err = addExtraAddresses(initialConfig.Addresses)
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
		RxQueueSize:    params.TapRxQueueSize,
		TxQueueSize:    params.TapTxQueueSize,
		Flags:          types.TapFlagTun,
	})
	if err != nil {
		return errors.Wrap(err, "Error creating tap")
	}
	err = writeFile(strconv.FormatInt(int64(tapSwIfIndex), 10), VppManagerTapIdxFile)
	if err != nil {
		return errors.Wrap(err, "Error writing tap idx")
	}

	err = vpp.SetInterfaceRxMode(tapSwIfIndex, types.AllQueues, params.tapRxMode)
	if err != nil {
		log.Errorf("Error SetInterfaceRxMode on vpptap0 %v", err)
	}

	err = configurePunt(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error adding redirect to tap")
	}

	err = vpp.InterfaceSetUnnumbered(tapSwIfIndex, DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting vpp tap unnumbered")
	}

	// Linux side tap setup
	link, err = netlink.LinkByName(HostIfName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", HostIfName)
	}

	err = configureLinuxTap(link)
	if err != nil {
		return errors.Wrap(err, "Error configure tap linux side")
	}

	err = configureLinuxTapRoutes(link)
	if err != nil {
		return errors.Wrap(err, "Error configuring vpp side ipv4 tap")
	}

	err = vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error setting tap up")
	}

	// TODO should watch for service prefix and ip pools to always route them through VPP
	// Service prefix is needed even if kube-proxy is running on the host to ensure correct source address selection
	return nil
}

func updateCalicoNode() (err error) {
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
		node, err = client.Nodes().Get(ctx, params.nodeName, calicoopts.GetOptions{})
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
		if initialConfig.Hasv4 {
			log.Infof("Setting BGP nodeIP %s", initialConfig.NodeIP4)
			if node.Spec.BGP.IPv4Address != initialConfig.NodeIP4 {
				node.Spec.BGP.IPv4Address = initialConfig.NodeIP4
				needUpdate = true
			}
		}
		if initialConfig.Hasv6 {
			log.Infof("Setting BGP nodeIP %s", initialConfig.NodeIP6)
			if node.Spec.BGP.IPv6Address != initialConfig.NodeIP6 {
				node.Spec.BGP.IPv6Address = initialConfig.NodeIP6
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

func CreateNativeMainInterface() error {
	if params.nativeDriver == NATIVE_DRIVER_AF_PACKET {
		swIfIndex, err := vpp.CreateAfPacket(params.mainInterface, &initialConfig.HardwareAddr)
		log.Infof("Created AF_PACKET %d", int(swIfIndex))
		return err
	} else if params.nativeDriver == NATIVE_DRIVER_AF_XDP {
		intf := types.VppXDPInterface{
			HostInterfaceName: params.mainInterface,
			RxQueueSize:       params.RxQueueSize,
			TxQueueSize:       params.TxQueueSize,
			NumRxQueues:       params.NumRxQueues,
		}
		err := vpp.CreateAfXDP(&intf)
		log.Infof("Created AF_XDP %d", int(intf.SwIfIndex))
		return err
	}
	return nil
}

func setInterfaceRxQueues(ifname string, queues int) error {
	/* TODO: use go library */
	cmd := exec.Command("ethtool", "-L", ifname, "combined", fmt.Sprintf("%d", queues))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func preConfigureLinuxMainInterface() (err error) {
	if initialConfig.IsUp && params.nativeDriver != NATIVE_DRIVER_AF_XDP {
		// Set interface down if it is up, bind it to a VPP-friendly driver
		link, err := netlink.LinkByName(params.mainInterface)
		if err != nil {
			return errors.Wrapf(err, "Error finding link %s", params.mainInterface)
		}
		err = netlink.LinkSetDown(link)
		if err != nil {
			// In case it still succeeded
			netlink.LinkSetUp(link)
			return errors.Wrapf(err, "Error setting link %s down", params.mainInterface)
		}
	}
	if initialConfig.DoSwapDriver {
		if initialConfig.PciId == "" {
			log.Warnf("PCI ID not found, not swapping drivers")
		} else {
			err = swapDriver(initialConfig.PciId, params.newDriverName, true)
			if err != nil {
				log.Warnf("Failed to swap driver to %s: %v", params.newDriverName, err)
			}
		}
	}
	if params.nativeDriver == NATIVE_DRIVER_AF_XDP {
		link, err := netlink.LinkByName(params.mainInterface)
		if err != nil {
			return errors.Wrapf(err, "Error finding link %s", params.mainInterface)
		}
		err = netlink.SetPromiscOn(link)
		if err != nil {
			return errors.Wrapf(err, "Error setting link %s promisc on", params.mainInterface)
		}
		err = setInterfaceRxQueues(params.mainInterface, params.NumRxQueues)
		if err != nil {
			return errors.Wrapf(err, "Error setting link %s NumQueues to %d", params.mainInterface, params.NumRxQueues)
		}
	}
	return nil
}

// Returns VPP exit code
func runVpp() (err error) {
	// From this point it is very important that every exit path calls restoreLinuxConfig after vpp exits
	// Bind the interface to a suitable drivr for VPP. DPDK does it automatically, this is useful otherwise
	vppCmd = exec.Command(VppPath, "-c", VppConfigFile)
	vppCmd.Stdout = os.Stdout
	vppCmd.Stderr = os.Stderr
	err = vppCmd.Start()
	if err != nil {
		restoreConfiguration()
		return errors.Wrap(err, "Error starting vpp process")
	}
	vppProcess = vppCmd.Process
	log.Infof("VPP started [PID %d]", vppProcess.Pid)
	runningCond.Broadcast()

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(params.vppStartupSleepSeconds) * time.Second)

	vpp, err = createVppLink()
	if err != nil {
		terminateVpp("Error connecting to VPP (SIGINT %d): %v", vppProcess.Pid, err)
		vpp.Close()
		<-vppDeadChan
		restoreConfiguration()
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}

	if params.nativeDriver != NATIVE_DRIVER_NONE {
		initialConfig.PciId = ""
		initialConfig.Driver = ""
		err = vpp.Retry(2*time.Second, 10, CreateNativeMainInterface)
		if err != nil {
			terminateVpp("Error creating af_packet (SIGINT %d): %v", vppProcess.Pid, err)
			vpp.Close()
			<-vppDeadChan
			restoreConfiguration()
			return errors.Wrap(err, "Error creating af_packet")
		}
	}

	// Data interface configuration
	err = vpp.Retry(2*time.Second, 10, vpp.InterfaceAdminUp, DataInterfaceSwIfIndex)
	if err != nil {
		terminateVpp("Error setting main interface up (SIGINT %d): %v", vppProcess.Pid, err)
		vpp.Close()
		<-vppDeadChan
		restoreConfiguration()
		return errors.Wrap(err, "Error setting data interface up")
	}

	// Configure VPP
	err = configureVpp(vpp)
	vpp.Close()
	if err != nil {
		<-vppDeadChan
		terminateVpp("Error configuring VPP (SIGINT %d): %v", vppProcess.Pid, err)
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = updateCalicoNode()
	if err != nil {
		terminateVpp("Error updating Calico node (SIGINT %d): %v", vppProcess.Pid, err)
		<-vppDeadChan
		restoreConfiguration()
		return errors.Wrap(err, "Error updating Calico node")
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

func setCorePattern() error {
	if params.corePattern == "" {
		return nil
	}
	err := writeFile(params.corePattern, "/proc/sys/kernel/core_pattern")
	if err != nil {
		return errors.Wrap(err, "Error writing corePattern")
	}
	return nil
}

func printVppManagerConfig() {
	log.Infof("CorePattern:         %s", params.corePattern)
	log.Infof("ExtraAddrCount:      %d", params.extraAddrCount)
	log.Infof("Native driver:       %s", params.nativeDriver)
	log.Infof("RxMode:              %s", formatRxMode(params.rxMode))
	log.Infof("TapRxMode:           %s", formatRxMode(params.tapRxMode))
	log.Infof("Node IP4:            %s", initialConfig.NodeIP4)
	log.Infof("Node IP6:            %s", initialConfig.NodeIP6)
	log.Infof("PciId:               %s", initialConfig.PciId)
	log.Infof("Driver:              %s", initialConfig.Driver)
	log.Infof("Linux if is up:      %t", initialConfig.IsUp)
	log.Infof("Promisc was :        %t", initialConfig.PromiscOn)
	log.Infof("DoSwapDriver:        %t", initialConfig.DoSwapDriver)
	log.Infof("Mac:                 %s", initialConfig.HardwareAddr.String())
	log.Infof("Addresses:           [%s]", initialConfig.AddressString())
	log.Infof("Routes:              [%s]", initialConfig.RouteString())
	log.Infof("Service CIDRs:       [%s]", ServiceCIDRsString())
	log.Infof("Tap Queue Size:      rx:%d tx:%d", params.TapRxQueueSize, params.TapTxQueueSize)
	log.Infof("PHY Queue Size:      rx:%d tx:%d", params.RxQueueSize, params.TxQueueSize)
	log.Infof("PHY original #Queues rx:%d tx:%d", initialConfig.NumRxQueues, initialConfig.NumTxQueues)
	log.Infof("PHY target #Queues   rx:%d", params.NumRxQueues)
}

func main() {
	vppDeadChan = make(chan bool, 1)
	vppAlive = false

	err := parseEnvVariables()
	if err != nil {
		log.Errorf("Error parsing env variables: %+v", err)
		return
	}

	err = clearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing config files: %+v", err)
		return
	}

	/* Run this before getLinuxConfig() in case this is a script
	 * that's responsible for creating the interface */

	err = setCorePattern()
	if err != nil {
		log.Errorf("Error setting core pattern: %s", err)
		return
	}

	err = configureContainer()
	if err != nil {
		log.Errorf("Error during initial config:")
	}

	checkDrivers()

	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()

	err = runInitScript()
	if err != nil {
		log.Errorf("Error running init script: %s", err)
		return
	}

	err = getInterfaceConfig()
	if err != nil {
		log.Errorf("Error getting initial interface configuration: %s", err)
		return
	}

	printVppManagerConfig()

	err = generateVppConfigExecFile()
	if err != nil {
		log.Errorf("Error generating VPP config Exec: %s", err)
		return
	}

	err = generateVppConfigFile()
	if err != nil {
		log.Errorf("Error generating VPP config: %s", err)
		return
	}

	err = preConfigureLinuxMainInterface()
	if err != nil {
		log.Errorf("Error pre-configuring Linux main IF: %s", err)
		return
	}

	err = runVpp()
	if err != nil {
		log.Errorf("Error running VPP: %v", err)
	}
	return
}
