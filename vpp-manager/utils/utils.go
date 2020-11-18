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
		return errors.Errorf("Failed to write state to %s", path)
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

func GetInterfacePciId(interfaceName string) (string, error) {
	// We allow PCI not to be found e.g for AF_PACKET
	// Grab PCI id - last PCI id in the real path to /sys/class/net/<device name>
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", interfaceName)
	devicePath, err := realpath.Realpath(deviceLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot resolve pci device path for %s", interfaceName)
	}
	pciID := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]")
	matches := pciID.FindAllString(devicePath, -1)
	if matches == nil {
		return "", nil
	} else {
		PciId := matches[len(matches)-1]
		return PciId, nil
	}
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

func SafeSetInterfaceDownByName(interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", interfaceName)
	}
	err = netlink.LinkSetDown(link)
	if err != nil {
		// In case it still succeeded
		netlink.LinkSetUp(link)
		return errors.Wrapf(err, "Error setting link %s down", interfaceName)
	}
	return nil
}

func SafeSetInterfaceUpByName(interfaceName string) (link netlink.Link, err error) {
	retries := 0
	for {
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			retries += 1
			if retries >= 10 {
				return nil, errors.Wrapf(err, "Error finding link %s after %d tries", interfaceName, retries)
			}
			time.Sleep(500 * time.Millisecond)
		} else {
			log.Infof("found links %s after %d tries", interfaceName, retries)
			break
		}
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, errors.Wrapf(err, "Error setting link %s back up", interfaceName)
	}
	return link, nil
}
