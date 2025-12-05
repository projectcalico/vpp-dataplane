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
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	vppmanagerparams "github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

type VirtioDriver struct {
	UplinkDriverData
}

func (d *VirtioDriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true
	ret = d.params.LoadedDrivers[config.DriverVfioPci]
	if !ret && warn {
		d.log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		d.log.Warnf("VPP may fail to grab its interface")
	}
	supported = supported && ret

	ret = d.params.AvailableHugePages > 0
	if !ret && warn {
		d.log.Warnf("No hugepages configured, driver won't work")
	}
	supported = supported && ret

	ret = d.intf.State.Driver == config.DriverVirtioPci
	if !ret && warn {
		d.log.Warnf("Interface driver is <%s>, not %s", d.intf.State.Driver, config.DriverVirtioPci)
	}
	supported = supported && ret

	return supported
}

func (d *VirtioDriver) PreconfigureLinux() (err error) {
	newDriverName := d.intf.Spec.NewDriverName
	doSwapDriver := d.intf.State.DoSwapDriver
	if newDriverName == "" {
		newDriverName = config.DriverVfioPci
		doSwapDriver = config.DriverVfioPci != d.intf.State.Driver
	}

	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VfioUnsafeNoIommuModeNO {
		err := config.SetVfioEnableUnsafeNoIommuMode(config.VfioUnsafeNoIommuModeYES)
		if err != nil {
			return errors.Wrapf(err, "failed to configure vfio")
		}
	}
	d.removeLinuxIfConf(true /* down */)
	if doSwapDriver {
		err = config.SwapDriver(d.log, d.intf.State.PciID, newDriverName, true)
		if err != nil {
			d.log.Warnf("Failed to swap driver to %s: %v", newDriverName, err)
		}
	}
	return nil
}

func (d *VirtioDriver) RestoreLinux() {
	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VfioUnsafeNoIommuModeNO {
		err := config.SetVfioEnableUnsafeNoIommuMode(config.VfioUnsafeNoIommuModeNO)
		if err != nil {
			d.log.Warnf("Virtio restore error %v", err)
		}
	}
	if d.intf.State.PciID != "" && d.intf.State.Driver != "" {
		err := config.SwapDriver(d.log, d.intf.State.PciID, d.intf.State.Driver, false)
		if err != nil {
			d.log.Warnf("Error swapping back driver to %s for %s: %v", d.intf.State.Driver, d.intf.State.PciID, err)
		}
	}
	if !d.params.AllInterfacesPhysical() {
		err := d.moveInterfaceFromNS(d.intf.Spec.InterfaceName)
		if err != nil {
			d.log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}
	if !d.intf.State.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := config.SafeSetInterfaceUpByName(d.intf.Spec.InterfaceName)
	if err != nil {
		d.log.Warnf("Error setting %s up: %v", d.intf.Spec.InterfaceName, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *VirtioDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	intf := types.VirtioInterface{
		GenericVppInterface: d.getGenericVppInterface(),
		PciID:               d.intf.State.PciID,
	}
	swIfIndex, err := vpp.CreateVirtio(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating VIRTIO interface")
	}
	d.log.Infof("Created VIRTIO interface %d", swIfIndex)

	d.intf.Spec.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.intf.Spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewVirtioDriver(params *vppmanagerparams.VppManagerParams,
	intf *vppmanagerparams.VppManagerInterface,
	log *logrus.Entry) *VirtioDriver {
	return &VirtioDriver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverVirtio,
			params: params,
			intf:   intf,
			log:    log,
		},
	}
}
