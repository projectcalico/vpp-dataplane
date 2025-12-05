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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

type DefaultDriver struct {
	UplinkDriverData
}

func (d *DefaultDriver) IsSupported(warn bool) bool {
	if d.params.LoadedDrivers[config.DriverVfioPci] || d.params.LoadedDrivers[config.DriverUioPciGeneric] {
		return true
	}
	if warn {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
	return false
}

func (d *DefaultDriver) PreconfigureLinux() (err error) {
	d.removeLinuxIfConf(true /* down */)
	if d.conf.DoSwapDriver {
		if d.conf.PciID == "" {
			log.Warnf("PCI ID not found, not swapping drivers")
		} else {
			err = utils.SwapDriver(d.conf.PciID, d.intf.Spec.NewDriverName, true)
			if err != nil {
				log.Warnf("Failed to swap driver to %s: %v", d.intf.Spec.NewDriverName, err)
			}
		}
	}
	return nil
}

func (d *DefaultDriver) RestoreLinux() {
	if d.conf.PciID != "" && d.conf.Driver != "" {
		err := utils.SwapDriver(d.conf.PciID, d.conf.Driver, false)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", d.conf.Driver, d.conf.PciID, err)
		}
	}
	if !d.conf.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := utils.SafeSetInterfaceUpByName(d.intf.Spec.InterfaceName)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.intf.Spec.InterfaceName, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *DefaultDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	// If interface is still in the host, move it to vpp netns to allow creation of the tap
	err = d.moveInterfaceToNS(d.intf.Spec.InterfaceName, vppPid)
	if err != nil {
		log.Infof("Did NOT move interface %s to VPP netns: %v", d.intf.Spec.InterfaceName, err)
	} else {
		log.Infof("Moved interface %s to VPP netns", d.intf.Spec.InterfaceName)
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

func NewDefaultDriver(params *config.VppManagerParams, intf *config.VppManagerInterface) *DefaultDriver {
	return &DefaultDriver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverNone,
			params: params,
			intf:   intf,
		},
	}
}
