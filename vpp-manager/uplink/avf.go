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
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
)

type AVFDriver struct {
	UplinkDriverData
}

func (d *AVFDriver) IsSupported(warn bool) bool {
	if d.params.LoadedDrivers[config.DRIVER_VFIO_PCI] || d.params.LoadedDrivers[config.DRIVER_VFIO_PCI] {
		return true
	}
	if warn {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
	return false
}

func (d *AVFDriver) PreconfigureLinux() (err error) {
	if d.conf.IsUp {
		// Set interface down if it is up, bind it to a VPP-friendly driver
		err := utils.SafeSetInterfaceDownByName(d.params.MainInterface)
		if err != nil {
			return err
		}
	}
	if d.conf.DoSwapDriver {
		if d.conf.PciId == "" {
			log.Warnf("PCI ID not found, not swapping drivers")
		} else {
			err = utils.SwapDriver(d.conf.PciId, d.params.NewDriverName, true)
			if err != nil {
				log.Warnf("Failed to swap driver to %s: %v", d.params.NewDriverName, err)
			}
		}
	}
	return nil
}

func (d *AVFDriver) RestoreLinux() {
	if d.conf.PciId != "" && d.conf.Driver != "" {
		err := utils.SwapDriver(d.conf.PciId, d.conf.Driver, false)
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

func (d *AVFDriver) CreateMainVppInterface(vpp *vpplink.VppLink) error {
	// TODO
	return nil
}

func NewAVFDriver(params *config.VppManagerParams, conf *config.InterfaceConfig) *AVFDriver {
	d := &AVFDriver{}
	d.name = NATIVE_DRIVER_AVF
	d.conf = conf
	d.params = params
	return d
}
