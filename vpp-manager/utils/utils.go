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

package utils

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/yookoala/realpath"
)

func IsDriverLoaded(driver string) (bool, error) {
	_, err := os.Stat("/sys/bus/pci/drivers/" + driver)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func GetMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func GetMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := GetMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func WriteFile(state string, path string) error {
	err := ioutil.WriteFile(path, []byte(state+"\n"), 0400)
	if err != nil {
		return errors.Errorf("Failed to write state to %s %s", path, err)
	}
	return nil
}

func RouteIsIP6(r *netlink.Route) bool {
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

func RouteIsLinkLocalUnicast(r *netlink.Route) bool {
	if r.Dst == nil {
		return false
	}
	if !vpplink.IsIP6(r.Dst.IP) {
		return false
	}
	return r.Dst.IP.IsLinkLocalUnicast()
}

func SetInterfaceRxQueues(ifname string, queues int) error {
	/* TODO: use go library */
	cmd := exec.Command("ethtool", "-L", ifname, "combined", fmt.Sprintf("%d", queues))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func SwapDriver(pciDevice, newDriver string, addId bool) error {
	if pciDevice == "" {
		log.Warnf("PCI ID not found, not swapping drivers")
		return nil
	}
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

func FormatIPNetSlice(lst []net.IPNet) string {
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return strings.Join(strLst, ", ")
}

func SetCorePattern(corePattern string) error {
	if corePattern == "" {
		return nil
	}
	err := WriteFile(corePattern, "/proc/sys/kernel/core_pattern")
	if err != nil {
		return errors.Wrap(err, "Error writing corePattern")
	}
	return nil
}

func SetRLimitMemLock() error {
	err := syscall.Setrlimit(8, &syscall.Rlimit{
		Cur: ^uint64(0),
		Max: ^uint64(0),
	}) // 8 - RLIMIT_MEMLOCK
	if err != nil {
		return err
	}
	return nil
}

func CreateVppLink() (vpp *vpplink.VppLink, err error) {
	// Get an API connection, with a few retries to accomodate VPP startup time
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(config.VppApiSocket, log.WithFields(log.Fields{"component": "vpp-api"}))
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

func ClearVppManagerFiles() error {
	err := WriteFile("0", config.VppManagerStatusFile)
	if err != nil {
		return err
	}
	return WriteFile("-1", config.VppManagerTapIdxFile)
}

func SetVfioUnsafeiommu(iommu bool) error {
	if iommu {
		return WriteFile("Y", "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	} else {
		return WriteFile("Y", "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	}
}

func IsVfioUnsafeiommu() (bool, error) {
	iommuStr, err := ioutil.ReadFile("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	if err != nil {
		return false, errors.Wrapf(err, "Couldnt read /sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	}
	iommu := "Y" == strings.TrimSpace(string(iommuStr))
	return iommu, nil
}

func DeleteInterfaceVF(pciId string) (err error) {
	sriovNumvfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciId)
	err = WriteFile("0", sriovNumvfsPath)
	if err != nil {
		return errors.Wrapf(err, "cannot disable VFs for %s", pciId)
	}
	return nil
}

func GetInterfaceNumVFs(pciId string) (int, error) {
	sriovNumvfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciId)
	numVfsStr, err := ioutil.ReadFile(sriovNumvfsPath)
	if err != nil {
		return 0, errors.Wrapf(err, "/sys/bus/pci/devices/%s/sriov_numvfs", pciId)
	}
	numVfs, err := strconv.ParseInt(strings.TrimSpace(string(numVfsStr)), 10, 32)
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt parse sriov_numvfs: %v", err)
	}
	return int(numVfs), nil
}

func SetVFSpoofTrust(ifName string, vf int, spoof bool, trust bool) error {
	spoofOn := "off"
	trustOn := "off"
	if spoof {
		spoofOn = "on"
	}
	if trust {
		trustOn = "on"
	}
	cmd := exec.Command("ip", "link", "set", "dev", ifName,
		"vf", fmt.Sprintf("%d", vf),
		"spoof", spoofOn,
		"trust", trustOn)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func GetInterfaceVFPciId(pciId string) (vfPciId string, err error) {
	virtfn0Path := fmt.Sprintf("/sys/bus/pci/devices/%s/virtfn0", pciId)
	vfPciId, err = getPciIdFromLink(virtfn0Path)
	if err != nil {
		return "", errors.Wrapf(err, "Couldn't find VF pciID in %s", virtfn0Path)
	}
	return vfPciId, nil
}

func CreateInterfaceVF(pciId string) error {
	numVfs, err := GetInterfaceNumVFs(pciId)
	if err != nil {
		return errors.Wrapf(err, "cannot get num VFs for %s", pciId)
	}

	if numVfs == 0 {
		/* Create a VF only if none is available */
		sriovNumvfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciId)
		err = WriteFile("1", sriovNumvfsPath)
		if err != nil {
			return errors.Wrapf(err, "cannot add VFs for %s", pciId)
		}
	}
	return nil
}

func BindVFtoDriver(pciId string, driver string) error {
	unbindPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver/unbind", pciId)
	err := WriteFile(pciId, unbindPath)
	if err != nil {
		return errors.Wrapf(err, "cannot unbind VF %s", pciId)
	}

	overridePath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver_override", pciId)
	err = WriteFile(driver, overridePath)
	if err != nil {
		return errors.Wrapf(err, "cannot override VF %s driver to %s", pciId, driver)
	}

	vfPciBindPath := fmt.Sprintf("/sys/bus/pci/drivers/%s/bind", driver)
	err = WriteFile(pciId, vfPciBindPath)
	if err != nil {
		return errors.Wrapf(err, "cannot bind VF %s to %s", pciId, driver)
	}

	err = WriteFile("", overridePath)
	if err != nil {
		return errors.Wrapf(err, "cannot remove VF %s override driver", pciId)
	}

	return nil
}

func GetInterfaceNameFromPci(pciId string) (string, error) {
	// Grab Driver id for the pci device
	driverLinkPath := fmt.Sprintf("/sys/bus/pci/devices/%s/net", pciId)
	netDevs, err := ioutil.ReadDir(driverLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot list /net for %s", pciId)
	}
	if len(netDevs) != 1 {
		return "", errors.Wrapf(err, "Found %d devices in /net for %s", len(netDevs), pciId)
	}
	return netDevs[0].Name(), nil
}

func GetDriverNameFromPci(pciId string) (string, error) {
	// Grab Driver id for the pci device
	driverLinkPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver", pciId)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot find driver for %s", pciId)
	}
	driver := driverPath[strings.LastIndex(driverPath, "/")+1:]
	return driver, nil
}

func getPciIdFromLink(path string) (string, error) {
	realPath, err := realpath.Realpath(path)
	if err != nil {
		return "", err
	}
	pciID := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]")
	matches := pciID.FindAllString(realPath, -1)
	if matches == nil {
		return "", nil
	} else {
		PciId := matches[len(matches)-1]
		return PciId, nil
	}
}

func GetInterfacePciId(interfaceName string) (string, error) {
	// We allow PCI not to be found e.g for AF_PACKET
	// Grab PCI id - last PCI id in the real path to /sys/class/net/<device name>
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", interfaceName)
	pciId, err := getPciIdFromLink(deviceLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot resolve pci device path for %s", interfaceName)
	}
	return pciId, nil
}

func GetNrHugepages() (int, error) {
	nrHugepagesStr, err := ioutil.ReadFile("/proc/sys/vm/nr_hugepages")
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt read /proc/sys/vm/nr_hugepages")
	}
	nrHugepages, err := strconv.ParseInt(strings.TrimSpace(string(nrHugepagesStr)), 10, 32)
	if err != nil {
		return 0, errors.Wrapf(err, "Couldnt parse nrHugepages: %v", err)
	}
	return int(nrHugepages), nil
}

func ParseKernelVersion(versionStr string) (ver *config.KernelVersion, err error) {
	re := regexp.MustCompile(`([0-9]+)\.([0-9]+)\.([0-9]+)\-([0-9]+)`)
	match := re.FindStringSubmatch(versionStr)
	if len(match) != 5 {
		return nil, errors.Errorf("Couldnt parse kernel version %s : %v", versionStr, match)
	}
	/* match[0] is the whole string */
	kernel, err := strconv.ParseInt(match[1], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldnt parse kernel version: %v", err)
	}
	major, err := strconv.ParseInt(match[2], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldnt parse major version: %v", err)
	}
	minor, err := strconv.ParseInt(match[3], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldnt parse minor version: %v", err)
	}
	patch, err := strconv.ParseInt(match[4], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldnt parse patch version: %v", err)
	}
	ver = &config.KernelVersion{
		Kernel: int(kernel),
		Major:  int(major),
		Minor:  int(minor),
		Patch:  int(patch),
	}
	return ver, nil
}

func GetOsKernelVersion() (ver *config.KernelVersion, err error) {
	versionStr, err := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return nil, errors.Wrapf(err, "Couldnt read /proc/sys/kernel/osrelease")
	}
	ver, err = ParseKernelVersion(strings.TrimSpace(string(versionStr)))
	return ver, err
}

func SafeGetLink(interfaceName string) (link netlink.Link, err error) {
	retries := 0
	for {
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			retries += 1
			if retries >= 20 {
				return nil, errors.Wrapf(err, "Error finding link %s after %d tries", interfaceName, retries)
			}
			time.Sleep(500 * time.Millisecond)
		} else {
			return link, nil
		}
	}
}

func SafeSetInterfaceUpByName(interfaceName string) (link netlink.Link, err error) {
	link, err = SafeGetLink(interfaceName)
	if err != nil {
		return nil, err
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, errors.Wrapf(err, "Error setting link %s back up", interfaceName)
	}
	return link, nil
}

func CycleHardwareAddr(hwAddr net.HardwareAddr, n uint8) net.HardwareAddr {
	/* Cycle the last n bits of hwaddr
	 * Given n <= 8 */
	hw := make([]byte, len(hwAddr))
	copy(hw, hwAddr)
	i := hw[len(hw)-1]
	lmask := byte((1 << n) - 1)       /* last n bits mask */
	tmask := byte(0xff & (0xff << n)) /* top n bits mask */
	nmask := byte(1 << (n - 1))       /* nth bit mask */
	i = (i & tmask) | (((i & lmask) << 1) & lmask) | (i & nmask)
	hw[len(hw)-1] = i
	return hw
}

func RenameInterface(name, newName string) (err error) {
	link, err := SafeGetLink(name)
	if err != nil {
		return errors.Wrapf(err, "error finding link %s", name)
	}

	isUp := (link.Attrs().Flags & net.FlagUp) != 0

	if isUp {
		if err = netlink.LinkSetDown(link); err != nil {
			netlink.LinkSetUp(link)
			return errors.Wrapf(err, "cannot set link %s down", name)
		}
	}

	if err = netlink.LinkSetName(link, newName); err != nil {
		netlink.LinkSetUp(link)
		return errors.Wrapf(err, "cannot rename link %s to %s", name, newName)
	}

	if isUp {
		err = netlink.LinkSetUp(link)
		return errors.Wrapf(err, "cannot set link %s up", newName)
	}
	return nil
}

func NormalizeIP(in net.IP) net.IP {
	if out := in.To4(); out != nil {
		return out
	}
	return in.To16()
}

// IncrementIP returns the given IP + 1
func IncrementIP(ip net.IP) (result net.IP) {
	ip = NormalizeIP(ip)
	result = make([]byte, len(ip))

	carry := true
	for i := len(ip) - 1; i >= 0; i-- {
		result[i] = ip[i]
		if carry {
			result[i]++
			if result[i] != 0 {
				carry = false
			}
		}
	}
	return
}

// DecrementIP returns the given IP + 1
func DecrementIP(ip net.IP) (result net.IP) {
	ip = NormalizeIP(ip)
	result = make([]byte, len(ip))

	carry := true
	for i := len(ip) - 1; i >= 0; i-- {
		result[i] = ip[i]
		if carry {
			result[i]--
			if result[i] != 0xff {
				carry = false
			}
		}
	}
	return
}

// NetworkAddr returns the first address in the given network, or the network address.
func NetworkAddr(n *net.IPNet) net.IP {
	network := make([]byte, len(n.IP))
	for i := 0; i < len(n.IP); i++ {
		network[i] = n.IP[i] & n.Mask[i]
	}
	return network
}

// BroadcastAddr returns the last address in the given network, or the broadcast address.
func BroadcastAddr(n *net.IPNet) net.IP {
	broadcast := make([]byte, len(n.IP))
	for i := 0; i < len(n.IP); i++ {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}

func RunBashScript(script string) error {
	if script == "" {
		return nil
	}
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
