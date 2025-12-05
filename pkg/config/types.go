// Copyright (C) 2022 Cisco Systems Inc.
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
	_ "embed"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// UnsafeNoIommuMode represents the content of the /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
// file. The 'disabled' value is used when no iommu is available in the environment.
type UnsafeNoIommuMode string

const (
	VfioUnsafeNoIommuModeYES      UnsafeNoIommuMode = "Y"
	VfioUnsafeNoIommuModeNO       UnsafeNoIommuMode = "N"
	VfioUnsafeNoIommuModeDISABLED UnsafeNoIommuMode = "disabled"
)

func SetVfioEnableUnsafeNoIommuMode(mode UnsafeNoIommuMode) (err error) {
	if mode == VfioUnsafeNoIommuModeDISABLED {
		return
	}
	return WriteFile(string(mode), "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
}

func GetVfioEnableUnsafeNoIommuMode() (UnsafeNoIommuMode, error) {
	iommuStr, err := os.ReadFile("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VfioUnsafeNoIommuModeDISABLED, nil
		}
		return VfioUnsafeNoIommuModeDISABLED, errors.Wrapf(err, "Couldnt read /sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
	}
	if strings.TrimSpace(string(iommuStr)) == "Y" {
		return VfioUnsafeNoIommuModeYES, nil
	} else {
		return VfioUnsafeNoIommuModeNO, nil
	}
}

type BGPServerModeType string

const (
	BGPServerModeDualStack BGPServerModeType = "dualStack"
	BGPServerModeV4Only    BGPServerModeType = "v4Only"
)

// IPFamilyConfig declares which IP families are expected to be present on an uplink interface.
type IPFamilyConfig string

const (
	// IPFamilyV4 requires an IPv4 address on the uplink.
	IPFamilyV4 IPFamilyConfig = "IPv4"
	// IPFamilyV6 requires an IPv6 address on the uplink.
	IPFamilyV6 IPFamilyConfig = "IPv6"
	// IPFamilyDualStack requires both an IPv4 and an IPv6 address on the uplink.
	IPFamilyDualStack IPFamilyConfig = "IPv4,IPv6"
)

func (f IPFamilyConfig) RequiresV4() bool {
	return f == IPFamilyV4 || f == IPFamilyDualStack
}

func (f IPFamilyConfig) RequiresV6() bool {
	return f == IPFamilyV6 || f == IPFamilyDualStack
}

func (f IPFamilyConfig) Validate() error {
	switch f {
	case IPFamilyV4, IPFamilyV6, IPFamilyDualStack, "":
		return nil
	default:
		return errors.Errorf("invalid ipFamilies value %q: must be %q, %q, or %q",
			f, IPFamilyV4, IPFamilyV6, IPFamilyDualStack)
	}
}

const (
	DriverUioPciGeneric = "uio_pci_generic"
	DriverVfioPci       = "vfio-pci"
	DriverVirtioPci     = "virtio-pci"
	DriverI40E          = "i40e"
	DriverICE           = "ice"
	DriverMLX5Core      = "mlx5_core"
	DriverVmxNet3       = "vmxnet3"
)
