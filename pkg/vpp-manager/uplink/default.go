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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	vppmanagerparams "github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
)

type DefaultDriver struct {
	UplinkDriverData
}

func (d *DefaultDriver) IsSupported(warn bool) bool {
	if d.params.LoadedDrivers[config.DriverVfioPci] || d.params.LoadedDrivers[config.DriverUioPciGeneric] {
		return true
	}
	if warn {
		d.log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		d.log.Warnf("VPP may fail to grab its interface")
	}
	return false
}

func (d *DefaultDriver) PreconfigureLinux() (err error) {
	d.removeLinuxIfConf(true /* down */)
	if d.intf.State.DoSwapDriver {
		if d.intf.State.PciID == "" {
			d.log.Warnf("PCI ID not found, not swapping drivers")
		} else {
			err = config.SwapDriver(d.log, d.intf.State.PciID, d.intf.Spec.NewDriverName, true)
			if err != nil {
				d.log.Warnf("Failed to swap driver to %s: %v", d.intf.Spec.NewDriverName, err)
			}
		}
	}
	return nil
}

func (d *DefaultDriver) RestoreLinux() {
	if d.intf.State.PciID != "" && d.intf.State.Driver != "" {
		err := config.SwapDriver(d.log, d.intf.State.PciID, d.intf.State.Driver, false)
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
}

func (d *DefaultDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	// If interface is still in the host, move it to vpp netns to allow creation of the tap
	err = d.moveInterfaceToNS(d.intf.Spec.InterfaceName, vppPid)
	if err != nil {
		d.log.Infof("Did NOT move interface %s to VPP netns: %v", d.intf.Spec.InterfaceName, err)
	} else {
		d.log.Infof("Moved interface %s to VPP netns", d.intf.Spec.InterfaceName)
	}
	// refusing to run on secondary interfaces as we have no way to figure out the sw_if_index
	if !d.intf.Spec.IsMain {
		return fmt.Errorf("%s driver not supported for secondary interfaces", d.name)
	}
	swIfIndex, err := vpp.SearchInterfaceWithTag("main-" + d.intf.Spec.InterfaceName)
	if err != nil {
		return fmt.Errorf("error trying to find interface with tag main-%s", d.intf.Spec.InterfaceName)
	}
	d.intf.Spec.SwIfIndex = swIfIndex
	return nil
}

func NewDefaultDriver(params *vppmanagerparams.VppManagerParams,
	intf *vppmanagerparams.VppManagerInterface,
	log *logrus.Entry) *DefaultDriver {
	return &DefaultDriver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverNone,
			params: params,
			intf:   intf,
			log:    log,
		},
	}
}
