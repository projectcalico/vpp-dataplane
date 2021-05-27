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
	log "github.com/sirupsen/logrus"
)

type RDMADriver struct {
	UplinkDriverData
}

func (d *RDMADriver) IsSupported(warn bool) (supported bool) {
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

	ret = d.conf.Driver == config.DRIVER_VIRTIO_PCI
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.conf.Driver, config.DRIVER_VIRTIO_PCI)
	}
	supported = supported && ret

	return supported
}

func (d *RDMADriver) PreconfigureLinux() (err error) {
	newDriverName := d.params.NewDriverName
	doSwapDriver := d.conf.DoSwapDriver
	/*if newDriverName == "" {
		newDriverName = config.DRIVER_VFIO_PCI
		doSwapDriver = config.DRIVER_VFIO_PCI != d.conf.Driver
	}*/

	/*if !d.params.VfioUnsafeiommu {
		err := utils.SetVfioUnsafeiommu(true)
		if err != nil {
			return errors.Wrapf(err, "Virtio preconfigure error")
		}
	}*/
	d.removeLinuxIfConf(true /* down */)
	if doSwapDriver {
		err = utils.SwapDriver(d.conf.PciId, newDriverName, true)
		if err != nil {
			log.Warnf("Failed to swap driver to %s: %v", newDriverName, err)
		}
	}
	return nil
}

func (d *RDMADriver) RestoreLinux() {
	if !d.params.VfioUnsafeiommu {
		err := utils.SetVfioUnsafeiommu(false)
		if err != nil {
			log.Warnf("Virtio restore error %v", err)
		}
	}
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

func (d *RDMADriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) (err error) {
	MyInfo := vpplink.RDMAInfo{
	d.params.MainInterface,
	d.params.NumRxQueues,
	d.params.RxQueueSize,
	d.params.TxQueueSize,
	}
	swIfIndex, err := vpp.CreateRDMA(MyInfo)

	if err != nil {
		return errors.Wrapf(err, "Error creating RDMA interface")
	}
	err = d.moveInterfaceToNS(d.params.MainInterface, vppPid)
	log.Errorf("Moving uplink in NS failed %s", err)

	log.Infof("Created RDMA interface %d", swIfIndex)

	if swIfIndex != config.DataInterfaceSwIfIndex {
		return fmt.Errorf("Created RDMA interface has wrong swIfIndex %d!", swIfIndex)
	}

	return nil
}

func NewRDMADriver(params *config.VppManagerParams, conf *config.InterfaceConfig) *RDMADriver {
	d := &RDMADriver{}
	d.name = NATIVE_DRIVER_RDMA
	d.conf = conf
	d.params = params
	return d
}
