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

type Vmxnet3Driver struct {
	UplinkDriverData
}

func (d *Vmxnet3Driver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true

	ret = d.intf.State.Driver == config.DriverVmxNet3
	if !ret && warn {
		d.log.Warnf("Interface driver is <%s>, not %s", d.intf.State.Driver, config.DriverVmxNet3)
	}
	supported = supported && ret

	return supported
}

func (d *Vmxnet3Driver) PreconfigureLinux() (err error) {
	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VfioUnsafeNoIommuModeNO {
		err := config.SetVfioEnableUnsafeNoIommuMode(config.VfioUnsafeNoIommuModeYES)
		if err != nil {
			return errors.Wrapf(err, "Vmxnet3 preconfigure error")
		}
	}
	d.removeLinuxIfConf(true /* down */)
	driverName, err := config.GetDriverNameFromPci(d.intf.State.PciID)
	if err != nil {
		return errors.Wrapf(err, "Couldnt get VF driver Name for %s", d.intf.State.PciID)
	}
	if driverName != config.DriverVfioPci {
		err := config.SwapDriver(d.log, d.intf.State.PciID, config.DriverVfioPci, true)
		if err != nil {
			return errors.Wrapf(err, "Couldnt swap %s to vfio_pci", d.intf.State.PciID)
		}
	}
	return nil
}

func (d *Vmxnet3Driver) RestoreLinux() {
	if d.intf.State.PciID != "" && d.intf.State.Driver != "" {
		err := config.SwapDriver(d.log, d.intf.State.PciID, d.intf.State.Driver, true)
		if err != nil {
			d.log.Warnf("Error swapping back driver to %s for %s: %v", d.intf.State.Driver, d.intf.State.PciID, err)
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

	if d.params.InitialVfioEnableUnsafeNoIommuMode == config.VfioUnsafeNoIommuModeNO {
		err = config.SetVfioEnableUnsafeNoIommuMode(config.VfioUnsafeNoIommuModeNO)
		if err != nil {
			d.log.Errorf("Vmxnet3 restore error %s", err)
		}
	}
}

func (d *Vmxnet3Driver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	intf := types.Vmxnet3Interface{
		GenericVppInterface: d.getGenericVppInterface(),
		EnableGso:           *config.GetCalicoVppDebug().GSOEnabled,
		PciID:               d.intf.State.PciID,
	}
	swIfIndex, err := vpp.CreateVmxnet3(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating Vmxnet3 interface")
	}

	d.log.Infof("Created Vmxnet3 interface %d", swIfIndex)

	d.intf.Spec.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.intf.Spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewVmxnet3Driver(params *vppmanagerparams.VppManagerParams,
	intf *vppmanagerparams.VppManagerInterface,
	log *logrus.Entry) *Vmxnet3Driver {
	return &Vmxnet3Driver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverVmxnet3,
			intf:   intf,
			params: params,
			log:    log,
		},
	}
}
