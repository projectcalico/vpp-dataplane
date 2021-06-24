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
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	log "github.com/sirupsen/logrus"
)

type Vmxnet3Driver struct {
	UplinkDriverData
}

func (d *Vmxnet3Driver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true

	ret = d.conf.Driver == config.DRIVER_VMXNET3
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.conf.Driver, config.DRIVER_VMXNET3)
	}
	supported = supported && ret

	return supported
}

func (d *Vmxnet3Driver) PreconfigureLinux() (err error) {
	if !d.params.VfioUnsafeiommu {
		err := utils.SetVfioUnsafeiommu(true)
		if err != nil {
			return errors.Wrapf(err, "Vmxnet3 preconfigure error")
		}
	}
	d.removeLinuxIfConf(true /* down */)
	driverName, err := utils.GetDriverNameFromPci(d.conf.PciId)
	if err != nil {
		return errors.Wrapf(err, "Couldnt get VF driver Name for %s", d.conf.PciId)
	}
	if driverName != config.DRIVER_VFIO_PCI {
		err := utils.SwapDriver(d.conf.PciId, config.DRIVER_VFIO_PCI, true)
		if err != nil {
			return errors.Wrapf(err, "Couldnt swap %s to vfio_pci", d.conf.PciId)
		}
	}
	return nil
}

func (d *Vmxnet3Driver) RestoreLinux() {
	if d.conf.PciId != "" && d.conf.Driver != "" {
		err := utils.SwapDriver(d.conf.PciId, d.conf.Driver, true)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", d.conf.Driver, d.conf.PciId, err)
		}
	}

	if !d.conf.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := utils.SafeSetInterfaceUpByName(d.params.MainInterface)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.params.MainInterface, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *Vmxnet3Driver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) (err error) {
	intf := types.Vmxnet3Interface{
		GenericVppInterface: d.getGenericVppInterface(),
		EnableGso:           d.params.EnableGSO,
		PciId:               d.conf.PciId,
	}
	swIfIndex, err := vpp.CreateVmxnet3(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating Vmxnet3 interface")
	}

	log.Infof("Created Vmxnet3 interface %d", swIfIndex)

	if swIfIndex != config.DataInterfaceSwIfIndex {
		return fmt.Errorf("created Vmxnet3 interface has wrong swIfIndex %d", swIfIndex)
	}

	return nil
}

func NewVmxnet3Driver(params *config.VppManagerParams, conf *config.InterfaceConfig) *Vmxnet3Driver {
	d := &Vmxnet3Driver{}
	d.name = NATIVE_DRIVER_VMXNET3
	d.conf = conf
	d.params = params
	return d
}
