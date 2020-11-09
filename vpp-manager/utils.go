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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

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

func setInterfaceRxQueues(ifname string, queues int) error {
	/* TODO: use go library */
	cmd := exec.Command("ethtool", "-L", ifname, "combined", fmt.Sprintf("%d", queues))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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

func FormatIPNetSlice(lst []net.IPNet) string {
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return strings.Join(strLst, ", ")
}

func setCorePattern(corePattern string) error {
	if corePattern == "" {
		return nil
	}
	err := writeFile(corePattern, "/proc/sys/kernel/core_pattern")
	if err != nil {
		return errors.Wrap(err, "Error writing corePattern")
	}
	return nil
}

func setRLimitMemLock() error {
	err := syscall.Setrlimit(8, &syscall.Rlimit{
		Cur: ^uint64(0),
		Max: ^uint64(0),
	}) // 8 - RLIMIT_MEMLOCK
	if err != nil {
		return err
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

func clearVppManagerFiles() error {
	err := writeFile("0", VppManagerStatusFile)
	if err != nil {
		return err
	}
	return writeFile("-1", VppManagerTapIdxFile)
}

