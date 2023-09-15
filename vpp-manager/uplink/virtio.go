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

package uplink

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type VirtioDriver struct {
	UplinkDriverData
}

func (d *VirtioDriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true
	ret = d.params.LoadedDrivers[config.DRIVER_VFIO_PCI]
	if !ret && warn {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
	supported = supported && ret

	ret = d.params.AvailableHugePages > 0
	if !ret && warn {
		log.Warnf("No hugepages configured, driver won't work")
	}
	supported = supported && ret

	ret = d.attachedInterface.LinuxConf.Driver == config.DRIVER_VIRTIO_PCI
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.attachedInterface.LinuxConf.Driver, config.DRIVER_VIRTIO_PCI)
	}
	supported = supported && ret

	return supported
}

func (d *VirtioDriver) PreconfigureLinux() (err error) {
	newDriverName := d.attachedInterface.NewDriverName
	doSwapDriver := d.attachedInterface.LinuxConf.DoSwapDriver
	if newDriverName == "" {
		newDriverName = config.DRIVER_VFIO_PCI
		doSwapDriver = config.DRIVER_VFIO_PCI != d.attachedInterface.LinuxConf.Driver
	}

	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VFIO_UNSAFE_NO_IOMMU_MODE_NO {
		err := utils.SetVfioEnableUnsafeNoIommuMode(config.VFIO_UNSAFE_NO_IOMMU_MODE_YES)
		if err != nil {
			return errors.Wrapf(err, "failed to configure vfio")
		}
	}
	d.removeLinuxIfConf(true /* down */)
	if doSwapDriver {
		err = utils.SwapDriver(d.attachedInterface.LinuxConf.PciId, newDriverName, true)
		if err != nil {
			log.Warnf("Failed to swap driver to %s: %v", newDriverName, err)
		}
	}
	return nil
}

func (d *VirtioDriver) RestoreLinux(allInterfacesPhysical bool) {
	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VFIO_UNSAFE_NO_IOMMU_MODE_NO {
		err := utils.SetVfioEnableUnsafeNoIommuMode(config.VFIO_UNSAFE_NO_IOMMU_MODE_NO)
		if err != nil {
			log.Warnf("Virtio restore error %v", err)
		}
	}
	if d.attachedInterface.LinuxConf.PciId != "" && d.attachedInterface.LinuxConf.Driver != "" {
		err := utils.SwapDriver(d.attachedInterface.LinuxConf.PciId, d.attachedInterface.LinuxConf.Driver, false)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", d.attachedInterface.LinuxConf.Driver, d.attachedInterface.LinuxConf.PciId, err)
		}
	}
	if !allInterfacesPhysical {
		err := d.moveInterfaceFromNS(d.attachedInterface.InterfaceName)
		if err != nil {
			log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}
	if !d.attachedInterface.LinuxConf.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := utils.SafeSetInterfaceUpByName(d.attachedInterface.InterfaceName)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.attachedInterface.InterfaceName, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *VirtioDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	intf := types.VirtioInterface{
		GenericVppInterface: d.getGenericVppInterface(),
		PciId:               d.attachedInterface.LinuxConf.PciId,
	}
	swIfIndex, err := vpp.CreateVirtio(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating VIRTIO interface")
	}
	log.Infof("Created VIRTIO interface %d", swIfIndex)

	d.attachedInterface.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.attachedInterface.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewVirtioDriver(params *config.VppManagerParams, idx int) *VirtioDriver {
	d := &VirtioDriver{}
	d.name = NATIVE_DRIVER_VIRTIO
	d.params = params
	d.attachedInterface = params.AttachedUplinksSpecs[idx]
	return d
}
