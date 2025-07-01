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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/yookoala/realpath"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
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
	err := os.WriteFile(path, []byte(state+"\n"), 0400)
	if err != nil {
		return errors.Errorf("Failed to write state to %s %s", path, err)
	}
	return nil
}

func WriteInfoFile() error {
	file, err := json.MarshalIndent(config.Info, "", " ")
	if err != nil {
		return errors.Errorf("Failed to encode json for info file: %s", err)
	}
	return os.WriteFile(config.VppManagerInfoFile, file, 0644)
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

func SwapDriver(pciDevice, newDriver string, addID bool) error {
	if pciDevice == "" {
		log.Warnf("PCI ID not found, not swapping drivers")
		return nil
	}
	deviceRoot := fmt.Sprintf("/sys/bus/pci/devices/%s", pciDevice)
	driverRoot := fmt.Sprintf("/sys/bus/pci/drivers/%s", newDriver)
	if addID {
		// Grab device vendor and id
		vendor, err := os.ReadFile(deviceRoot + "/vendor")
		if err != nil {
			return errors.Wrapf(err, "Error reading device %s vendor", pciDevice)
		}
		device, err := os.ReadFile(deviceRoot + "/device")
		if err != nil {
			return errors.Wrapf(err, "Error reading device %s id", pciDevice)
		}
		// Add it to driver before unbinding to prevent spontaneous binds
		identifier := fmt.Sprintf("%s %s\n", string(vendor[2:6]), string(device[2:6]))
		log.Infof("Adding id '%s' to driver %s", identifier, newDriver)
		err = os.WriteFile(driverRoot+"/new_id", []byte(identifier), 0200)
		if err != nil {
			log.Warnf("Could not add id %s to driver %s: %v", identifier, newDriver, err)
		}
	}
	err := os.WriteFile(deviceRoot+"/driver/unbind", []byte(pciDevice), 0200)
	if err != nil {
		// Error on unbind is not critical, device might beind successfully afterwards if it is not currently bound
		log.Warnf("Error unbinding %s: %v", pciDevice, err)
	}
	err = os.WriteFile(driverRoot+"/bind", []byte(pciDevice), 0200)
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
	// Get an API connection, with a few retries to accommodate VPP startup time
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(config.VppAPISocket, log.WithFields(log.Fields{"component": "vpp-api"}))
		if err != nil {
			if i < 5 {
				/* do not warn, it is probably fine */
				log.Infof("Waiting for VPP... [%d/10]", i)
			} else {
				log.Warnf("Waiting for VPP... [%d/10] %v", i, err)
			}
			time.Sleep(2 * time.Second)
		} else {
			return vpp, nil
		}
	}
	return nil, errors.Errorf("Cannot connect to VPP after 10 tries")
}

func ClearVppManagerFiles() error {
	config.Info.Status = config.Starting
	config.Info.UplinkStatuses = make(map[string]config.UplinkStatus, 0)
	config.Info.PhysicalNets = make(map[string]config.PhysicalNetwork, 0)
	return WriteInfoFile()
}

func SetVfioEnableUnsafeNoIommuMode(mode config.UnsafeNoIommuMode) (err error) {
	if mode == config.VfioUnsafeNoIommuModeDISABLED {
		return
	}
	return WriteFile(string(mode), "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
}

func GetVfioEnableUnsafeNoIommuMode() (config.UnsafeNoIommuMode, error) {
	iommuStr, err := os.ReadFile("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.VfioUnsafeNoIommuModeDISABLED, nil
		}
		return config.VfioUnsafeNoIommuModeDISABLED, errors.Wrapf(err, "Couldnt read /sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	}
	if strings.TrimSpace(string(iommuStr)) == "Y" {
		return config.VfioUnsafeNoIommuModeYES, nil
	} else {
		return config.VfioUnsafeNoIommuModeNO, nil
	}
}

func DeleteInterfaceVF(pciID string) (err error) {
	sriovNumvfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciID)
	err = WriteFile("0", sriovNumvfsPath)
	if err != nil {
		return errors.Wrapf(err, "cannot disable VFs for %s", pciID)
	}
	return nil
}

func GetInterfaceNumVFs(pciID string) (int, error) {
	sriovNumvfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciID)
	numVfsStr, err := os.ReadFile(sriovNumvfsPath)
	if err != nil {
		return 0, errors.Wrapf(err, "/sys/bus/pci/devices/%s/sriov_numvfs", pciID)
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

/**
 * This function was copied from the following repo [0]
 * as we depend on pkg/ns, but it doesnot support netns creation
 * [0] github.com/containernetworking/plugins.git:pkg/testutils/netns_linux.go
 */
func getNsRunDir() string {
	xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")

	/// If XDG_RUNTIME_DIR is set, check if the current user owns /var/run.  If
	// the owner is different, we are most likely running in a user namespace.
	// In that case use $XDG_RUNTIME_DIR/netns as runtime dir.
	if xdgRuntimeDir != "" {
		if s, err := os.Stat("/var/run"); err == nil {
			st, ok := s.Sys().(*syscall.Stat_t)
			if ok && int(st.Uid) != os.Geteuid() {
				return path.Join(xdgRuntimeDir, "netns")
			}
		}
	}

	return "/var/run/netns"
}

// getCurrentThreadNetNSPath copied from containernetworking/plugins/pkg/ns
func getCurrentThreadNetNSPath() string {
	// /proc/self/ns/net returns the namespace of the main thread, not
	// of whatever thread this goroutine is running on.  Make sure we
	// use the thread's net namespace since the thread is switching around
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}

/**
 * This function was copied from the following repo [0]
 * as we depend on pkg/ns, but it doesnot support netns creation
 * [0] github.com/containernetworking/plugins.git:pkg/testutils/netns_linux.go
 */
func NewNS(nsName string) (ns.NetNS, error) {
	// Creates a new persistent (bind-mounted) network namespace and returns an object
	// representing that namespace, without switching to it.

	nsRunDir := getNsRunDir()

	// Create the directory for mounting network namespaces
	// This needs to be a shared mountpoint in case it is mounted in to
	// other namespaces (containers)
	err := os.MkdirAll(nsRunDir, 0755)
	if err != nil {
		return nil, err
	}

	// Remount the namespace directory shared. This will fail if it is not
	// already a mountpoint, so bind-mount it on to itself to "upgrade" it
	// to a mountpoint.
	err = unix.Mount("", nsRunDir, "none", unix.MS_SHARED|unix.MS_REC, "")
	if err != nil {
		if err != unix.EINVAL {
			return nil, fmt.Errorf("mount --make-rshared %s failed: %q", nsRunDir, err)
		}

		// Recursively remount /var/run/netns on itself. The recursive flag is
		// so that any existing netns bindmounts are carried over.
		err = unix.Mount(nsRunDir, nsRunDir, "none", unix.MS_BIND|unix.MS_REC, "")
		if err != nil {
			return nil, fmt.Errorf("mount --rbind %s %s failed: %q", nsRunDir, nsRunDir, err)
		}

		// Now we can make it shared
		err = unix.Mount("", nsRunDir, "none", unix.MS_SHARED|unix.MS_REC, "")
		if err != nil {
			return nil, fmt.Errorf("mount --make-rshared %s failed: %q", nsRunDir, err)
		}

	}

	// create an empty file at the mount point
	nsPath := path.Join(nsRunDir, nsName)
	mountPointFd, err := os.Create(nsPath)
	if err != nil {
		return nil, err
	}
	mountPointFd.Close()

	// Ensure the mount point is cleaned up on errors; if the namespace
	// was successfully mounted this will have no effect because the file
	// is in-use
	defer os.RemoveAll(nsPath)

	var wg sync.WaitGroup
	wg.Add(1)

	// do namespace work in a dedicated goroutine, so that we can safely
	// Lock/Unlock OSThread without upsetting the lock/unlock state of
	// the caller of this function
	go (func() {
		defer wg.Done()
		runtime.LockOSThread()
		// Don't unlock. By not unlocking, golang will kill the OS thread when the
		// goroutine is done (for go1.10+)

		var origNS ns.NetNS
		origNS, err = ns.GetNS(getCurrentThreadNetNSPath())
		if err != nil {
			return
		}
		defer origNS.Close()

		// create a new netns on the current thread
		err = unix.Unshare(unix.CLONE_NEWNET)
		if err != nil {
			return
		}

		// Put this thread back to the orig ns, since it might get reused (pre go1.10)
		defer func() {
			err2 := origNS.Set()
			if err2 != nil {
				err = fmt.Errorf("error setting origNS %s (origin err %s)", err2, err)
			}
		}()

		// bind mount the netns from the current thread (from /proc) onto the
		// mount point. This causes the namespace to persist, even when there
		// are no threads in the ns.
		err = unix.Mount(getCurrentThreadNetNSPath(), nsPath, "none", unix.MS_BIND, "")
		if err != nil {
			err = fmt.Errorf("failed to bind mount ns at %s: %v", nsPath, err)
		}
	})()
	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("failed to create namespace: %v", err)
	}

	return ns.GetNS(nsPath)
}

func GetnetnsPath(nsName string) string {
	return path.Join(getNsRunDir(), nsName)
}

func GetInterfaceVFPciID(pciID string) (vfPciID string, err error) {
	virtfn0Path := fmt.Sprintf("/sys/bus/pci/devices/%s/virtfn0", pciID)
	vfPciID, err = getPciIDFromLink(virtfn0Path)
	if err != nil {
		return "", errors.Wrapf(err, "Couldn't find VF pciID in %s", virtfn0Path)
	}
	return vfPciID, nil
}

func CreateInterfaceVF(pciID string) error {
	numVfs, err := GetInterfaceNumVFs(pciID)
	if err != nil {
		return errors.Wrapf(err, "cannot get num VFs for %s", pciID)
	}

	if numVfs == 0 {
		/* Create a VF only if none is available */
		sriovNumvfsPath := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciID)
		err = WriteFile("1", sriovNumvfsPath)
		if err != nil {
			return errors.Wrapf(err, "cannot add VFs for %s", pciID)
		}
	}
	return nil
}

func BindVFtoDriver(pciID string, driver string) error {
	unbindPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver/unbind", pciID)
	err := WriteFile(pciID, unbindPath)
	if err != nil {
		return errors.Wrapf(err, "cannot unbind VF %s", pciID)
	}

	overridePath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver_override", pciID)
	err = WriteFile(driver, overridePath)
	if err != nil {
		return errors.Wrapf(err, "cannot override VF %s driver to %s", pciID, driver)
	}

	vfPciBindPath := fmt.Sprintf("/sys/bus/pci/drivers/%s/bind", driver)
	err = WriteFile(pciID, vfPciBindPath)
	if err != nil {
		return errors.Wrapf(err, "cannot bind VF %s to %s", pciID, driver)
	}

	err = WriteFile("", overridePath)
	if err != nil {
		return errors.Wrapf(err, "cannot remove VF %s override driver", pciID)
	}

	return nil
}

func GetInterfaceNameFromPci(pciID string) (string, error) {
	// Grab Driver id for the pci device
	driverLinkPath := fmt.Sprintf("/sys/bus/pci/devices/%s/net", pciID)
	netDevs, err := os.ReadDir(driverLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot list /net for %s", pciID)
	}
	if len(netDevs) != 1 {
		return "", errors.Wrapf(err, "Found %d devices in /net for %s", len(netDevs), pciID)
	}
	return netDevs[0].Name(), nil
}

func GetDriverNameFromPci(pciID string) (string, error) {
	// Grab Driver id for the pci device
	driverLinkPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver", pciID)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot find driver for %s", pciID)
	}
	driver := driverPath[strings.LastIndex(driverPath, "/")+1:]
	return driver, nil
}

func getPciIDFromLink(path string) (string, error) {
	realPath, err := realpath.Realpath(path)
	if err != nil {
		return "", err
	}
	pciID := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]")
	matches := pciID.FindAllString(realPath, -1)
	if matches == nil {
		return "", nil
	} else {
		PciID := matches[len(matches)-1]
		return PciID, nil
	}
}

func GetInterfacePciID(interfaceName string) (string, error) {
	// Grab PCI id - last PCI id in the real path to /sys/class/net/<device name>
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", interfaceName)
	pciID, err := getPciIDFromLink(deviceLinkPath)
	if err != nil {
		return "", errors.Wrapf(err, "cannot resolve pci device path for %s", interfaceName)
	}
	return pciID, nil
}

func GetNrHugepages() (int, error) {
	nrHugepagesStr, err := os.ReadFile("/proc/sys/vm/nr_hugepages")
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
	versionStr, err := os.ReadFile("/proc/sys/kernel/osrelease")
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
			err2 := netlink.LinkSetUp(link)
			return errors.Wrapf(err, "cannot set link %s down (err2 %s)", name, err2)
		}
	}

	if err = netlink.LinkSetName(link, newName); err != nil {
		err2 := netlink.LinkSetUp(link)
		return errors.Wrapf(err, "cannot rename link %s to %s (err2 %s)", name, newName, err2)
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

func FetchNodeAnnotations(nodeName string) map[string]string {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return make(map[string]string)
	}

	k8sclient, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return make(map[string]string)
	}

	ctx, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel1()
	node, err := k8sclient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return make(map[string]string)
	}
	return node.Annotations
}

type timeAndPath struct {
	path    string
	modTime time.Time
}

type timeAndPathSlice []timeAndPath

func (s timeAndPathSlice) Less(i, j int) bool { return s[i].modTime.After(s[j].modTime) }
func (s timeAndPathSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s timeAndPathSlice) Len() int           { return len(s) }

// to avoid side effects we only check that the prefix match
func matchesCorePattern(fname, corePattern string) bool {
	splits := strings.SplitN(corePattern, "%", 2)
	return strings.HasPrefix(fname, splits[0])
}

func CleanupCoreFiles(corePattern string, maxCoreFiles int) error {
	if corePattern == "" {
		return nil
	}
	var timeAndPaths timeAndPathSlice = make([]timeAndPath, 0)
	directory, err := os.Open(filepath.Dir(corePattern))
	if err != nil {
		return errors.Wrap(err, "walk errored")
	}
	infos, err := directory.Readdir(-1)
	directory.Close()
	if err != nil {
		return errors.Wrap(err, "directory readdir errored")
	}
	for _, info := range infos {
		if !info.IsDir() && matchesCorePattern(info.Name(), filepath.Base(corePattern)) {
			timeAndPaths = append(timeAndPaths, timeAndPath{
				filepath.Join(filepath.Dir(corePattern), info.Name()),
				info.ModTime(),
			})
		}
	}
	// sort timeAndPaths by decreasing times
	sort.Sort(timeAndPaths)
	// we remove at most (2 * maxCoreFiles + 2) coredumps leaving the first maxCorefiles in place
	for i := maxCoreFiles; i < len(timeAndPaths) && (i-maxCoreFiles < maxCoreFiles+2); i++ {
		os.Remove(timeAndPaths[i].path)
	}

	if len(timeAndPaths) > 0 && maxCoreFiles > 0 {
		PrintLastBackTrace(timeAndPaths[0].path)
	}
	return nil
}

func PrintLastBackTrace(coreFile string) {
	if _, err := os.Stat("/usr/bin/gdb"); os.IsNotExist(err) {
		log.Infof("Found previous coredump %s, missing gdb for stacktrace", coreFile)
	} else {
		log.Infof("Found previous coredump %s, trying to print stacktrace", coreFile)
		cmd := exec.Command("/usr/bin/gdb", "-ex", "bt", "-ex", "q", "vpp", coreFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Start()
		if err != nil {
			log.Infof("gdb returned %s", err)
		}
	}
}
