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

package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type MachineState struct {
	LoadedDrivers                      map[string]bool
	KernelVersion                      *KernelVersion
	AvailableHugePages                 int
	InitialVfioEnableUnsafeNoIommuMode UnsafeNoIommuMode
	// VppManagerNs is the path to the vpp-manager golang
	// agent netns, where network is expected to be set up
	VppManagerNs string
}

func NewMachineState() *MachineState {
	params := &MachineState{
		VppManagerNs: "pid:1",
	}
	// Drivers
	params.LoadedDrivers = make(map[string]bool)
	vfioLoaded, err := isDriverLoaded(DriverVfioPci)
	if err != nil {
		log.Warnf("Error determining whether %s is loaded", DriverVfioPci)
	}
	params.LoadedDrivers[DriverVfioPci] = vfioLoaded
	uioLoaded, err := isDriverLoaded(DriverUioPciGeneric)
	if err != nil {
		log.Warnf("Error determining whether %s is loaded", DriverUioPciGeneric)
	}
	params.LoadedDrivers[DriverUioPciGeneric] = uioLoaded

	// AF XDP support
	kernel, err := getOsKernelVersion()
	if err != nil {
		log.Warnf("Error getting os kernel version %v", err)
	} else {
		params.KernelVersion = kernel
	}
	// Hugepages
	nrHugepages, err := getNrHugepages()
	if err != nil {
		log.Warnf("Error getting nrHugepages %v", err)
	}
	params.AvailableHugePages = nrHugepages
	/* Iommu */
	params.InitialVfioEnableUnsafeNoIommuMode, err = GetVfioEnableUnsafeNoIommuMode()
	if err != nil {
		log.Warnf("Error getting vfio iommu state %v", err)
	}
	return params
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

type KernelVersion struct {
	Kernel int
	Major  int
	Minor  int
	Patch  int
}

func (ver *KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d-%d", ver.Kernel, ver.Major, ver.Minor, ver.Patch)
}

func (ver *KernelVersion) IsAtLeast(other *KernelVersion) bool {
	if ver.Kernel < other.Kernel {
		return false
	}
	if ver.Major < other.Major {
		return false
	}
	if ver.Minor < other.Minor {
		return false
	}
	if ver.Patch < other.Patch {
		return false
	}
	return true
}

func ParseKernelVersion(versionStr string) (ver *KernelVersion, err error) {
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
	ver = &KernelVersion{
		Kernel: int(kernel),
		Major:  int(major),
		Minor:  int(minor),
		Patch:  int(patch),
	}
	return ver, nil
}

func getOsKernelVersion() (ver *KernelVersion, err error) {
	versionStr, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return nil, errors.Wrapf(err, "Couldnt read /proc/sys/kernel/osrelease")
	}
	ver, err = ParseKernelVersion(strings.TrimSpace(string(versionStr)))
	return ver, err
}

func getNrHugepages() (int, error) {
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
