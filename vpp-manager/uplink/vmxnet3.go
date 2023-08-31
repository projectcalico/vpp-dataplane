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

type Vmxnet3Driver struct {
	UplinkDriverData
}

func (d *Vmxnet3Driver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true

	ret = d.attachedInterface.LinuxConf.Driver == config.DRIVER_VMXNET3
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.attachedInterface.LinuxConf.Driver, config.DRIVER_VMXNET3)
	}
	supported = supported && ret

	return supported
}

func (d *Vmxnet3Driver) PreconfigureLinux() (err error) {
	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VFIO_UNSAFE_NO_IOMMU_MODE_NO {
		err := utils.SetVfioEnableUnsafeNoIommuMode(config.VFIO_UNSAFE_NO_IOMMU_MODE_YES)
		if err != nil {
			return errors.Wrapf(err, "Vmxnet3 preconfigure error")
		}
	}
	d.removeLinuxIfConf(true /* down */)
	driverName, err := utils.GetDriverNameFromPci(d.attachedInterface.LinuxConf.PciId)
	if err != nil {
		return errors.Wrapf(err, "Couldnt get VF driver Name for %s", d.attachedInterface.LinuxConf.PciId)
	}
	if driverName != config.DRIVER_VFIO_PCI {
		err := utils.SwapDriver(d.attachedInterface.LinuxConf.PciId, config.DRIVER_VFIO_PCI, true)
		if err != nil {
			return errors.Wrapf(err, "Couldnt swap %s to vfio_pci", d.attachedInterface.LinuxConf.PciId)
		}
	}
	return nil
}

func (d *Vmxnet3Driver) RestoreLinux(allInterfacesPhysical bool) {
	if d.attachedInterface.LinuxConf.PciId != "" && d.attachedInterface.LinuxConf.Driver != "" {
		err := utils.SwapDriver(d.attachedInterface.LinuxConf.PciId, d.attachedInterface.LinuxConf.Driver, true)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", d.attachedInterface.LinuxConf.Driver, d.attachedInterface.LinuxConf.PciId, err)
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

	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VFIO_UNSAFE_NO_IOMMU_MODE_NO {
		err = utils.SetVfioEnableUnsafeNoIommuMode(config.VFIO_UNSAFE_NO_IOMMU_MODE_NO)
		if err != nil {
			log.Errorf("Vmxnet3 restore error %s", err)
		}
	}
}

func (d *Vmxnet3Driver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	intf := types.Vmxnet3Interface{
		GenericVppInterface: d.getGenericVppInterface(),
		EnableGso:           *config.GetCalicoVppDebug().GSOEnabled,
		PciId:               d.attachedInterface.LinuxConf.PciId,
	}
	swIfIndex, err := vpp.CreateVmxnet3(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating Vmxnet3 interface")
	}

	log.Infof("Created Vmxnet3 interface %d", swIfIndex)

	d.attachedInterface.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.attachedInterface.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewVmxnet3Driver(params *config.VppManagerParams, idx int) *Vmxnet3Driver {
	d := &Vmxnet3Driver{}
	d.name = NATIVE_DRIVER_VMXNET3
	d.attachedInterface = params.AttachedUplinksSpecs[idx]
	d.params = params
	return d
}
