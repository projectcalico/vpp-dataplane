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
	gerrors "errors"
	"fmt"
	"regexp"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type DPDKDriver struct {
	UplinkDriverData
}

func (d *DPDKDriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true
	ret = d.attachedInterface.LinuxConf.PciId != ""
	if !ret && warn {
		log.Warnf("did not find  pci device id for interface")
	}
	supported = supported && ret
	return supported
}

func (d *DPDKDriver) getFinalDriver() string {
	if d.attachedInterface.LinuxConf.DoSwapDriver {
		return d.attachedInterface.NewDriverName
	}
	return d.attachedInterface.LinuxConf.Driver
}

func (d *DPDKDriver) PreconfigureLinux() (err error) {
	d.removeLinuxIfConf(true /* down */)
	if d.attachedInterface.LinuxConf.DoSwapDriver {
		err = utils.SwapDriver(d.attachedInterface.LinuxConf.PciId, d.attachedInterface.NewDriverName, true)
		if err != nil {
			log.Warnf("Failed to swap driver to %s: %v", d.attachedInterface.NewDriverName, err)
		}
	}
	if d.getFinalDriver() == config.DRIVER_VFIO_PCI &&
		d.params.AvailableHugePages == 0 &&
		d.params.InitialVfioEnableUnsafeNoIommuMode == config.VFIO_UNSAFE_NO_IOMMU_MODE_YES {
		err := utils.SetVfioEnableUnsafeNoIommuMode(config.VFIO_UNSAFE_NO_IOMMU_MODE_NO)
		if err != nil {
			return errors.Wrapf(err, "failed to configure vfio")
		}
	}
	return nil
}

func (d *DPDKDriver) UpdateVppConfigFile(template string) string {
	dpdkPluginRegex := regexp.MustCompile(`plugin\s+dpdk_plugin\.so\s*{\s*disable\s*}`)
	template = dpdkPluginRegex.ReplaceAllString(template, "plugin dpdk_plugin.so { enable }")

	dpdkStanzaRegex := regexp.MustCompile(`dpdk\s*{[^}]+}`)
	if dpdkStanzaRegex.MatchString(template) {
		goto write
	}

	if d.params.AvailableHugePages > 0 {
		template = fmt.Sprintf(
			"%s\ndpdk {\ndev %s { num-rx-queues %d num-tx-queues %d num-rx-desc %d num-tx-desc %d tag %s } \n}\n",
			template, d.attachedInterface.LinuxConf.PciId, d.attachedInterface.NumRxQueues, d.attachedInterface.NumTxQueues,
			d.attachedInterface.RxQueueSize, d.attachedInterface.TxQueueSize, "main-"+d.attachedInterface.InterfaceName,
		)

	} else {
		template = fmt.Sprintf(
			"%s\ndpdk {\niova-mode va\nno-hugetlb\ndev %s { num-rx-queues %d num-tx-queues %d num-rx-desc %d num-tx-desc %d tag %s } \n}\n",
			template, d.attachedInterface.LinuxConf.PciId, d.attachedInterface.NumRxQueues, d.attachedInterface.NumTxQueues,
			d.attachedInterface.RxQueueSize, d.attachedInterface.TxQueueSize, "main-"+d.attachedInterface.InterfaceName,
		)

		// If no hugepages, also edit `buffers {}`
		buffersHeadRegex := regexp.MustCompile(`buffers\s*{`)
		buffersStanzaRegex := regexp.MustCompile(`buffers\s*{[^}]+}`)
		buffersNoHugeStanzaRegex := regexp.MustCompile(`buffers\s*{[^}]*no-hugetlb[^}]*}`)
		if buffersStanzaRegex.MatchString(template) {
			if !buffersNoHugeStanzaRegex.MatchString(template) {
				template = buffersHeadRegex.ReplaceAllString(template, "buffers {\nno-hugetlb")
				log.Infof("Found buffers configuration in template")
			}
		} else {
			template = fmt.Sprintf("%s\nbuffers {\nno-hugetlb\n}", template)
		}
	}

write:
	return template
}

func (d *DPDKDriver) restoreInterfaceName() error {
	newName, err := utils.GetInterfaceNameFromPci(d.attachedInterface.LinuxConf.PciId)
	if err != nil {
		return errors.Wrapf(err, "Error getting new if name for %s: %v", newName, d.attachedInterface.LinuxConf.PciId)
	}
	if newName == d.attachedInterface.InterfaceName {
		return nil
	}
	link, err := netlink.LinkByName(newName)
	if err != nil {
		return errors.Wrapf(err, "Error getting new link %s: %v", newName, link)
	}
	err = netlink.LinkSetName(link, d.attachedInterface.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error setting new if name for %s: %v", d.attachedInterface.InterfaceName, link)
	}
	return nil
}

func (d *DPDKDriver) RestoreLinux(allInterfacesPhysical bool) {
	if d.attachedInterface.LinuxConf.PciId != "" && d.attachedInterface.LinuxConf.Driver != "" {
		err := utils.SwapDriver(d.attachedInterface.LinuxConf.PciId, d.attachedInterface.LinuxConf.Driver, false)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", d.attachedInterface.LinuxConf.Driver, d.attachedInterface.LinuxConf.PciId, err)
		}
	}

	for i := 0; i < 10; i++ {
		err := d.restoreInterfaceName()
		if err != nil {
			log.Warnf("Error restoring if name %s", err)
		} else {
			break
		}
		time.Sleep(500 * time.Millisecond)
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

	if d.getFinalDriver() == config.DRIVER_VFIO_PCI &&
		d.params.AvailableHugePages == 0 &&
		d.params.InitialVfioEnableUnsafeNoIommuMode == config.VFIO_UNSAFE_NO_IOMMU_MODE_YES {
		err = utils.SetVfioEnableUnsafeNoIommuMode(config.VFIO_UNSAFE_NO_IOMMU_MODE_YES)
		if err != nil {
			log.Errorf("failed to configure vfio %s", err)
		}
	}
}

func (d *DPDKDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	// Nothing to do VPP autocreates on startup
	// refusing to run on secondary interfaces as we have no way to figure out the sw_if_index
	if !d.attachedInterface.GetIsMain() {
		return fmt.Errorf("%s driver not supported for secondary interfaces", d.name)
	}
	swIfIndex, err := vpp.SearchInterfaceWithTag("main-" + d.attachedInterface.InterfaceName)
	if err != nil || swIfIndex == ^uint32(0) {
		return fmt.Errorf("error trying to find interface with tag main-%s", d.attachedInterface.InterfaceName)
	}
	log.Debugf("Found interface with swIfIndex %d for %s", swIfIndex, d.attachedInterface.InterfaceName)
	d.attachedInterface.SwIfIndex = swIfIndex
	err = vpp.SetInterfaceMacAddress(swIfIndex, d.attachedInterface.LinuxConf.HardwareAddr)
	if err != nil && gerrors.Is(err, types.VppErrorUnimplemented) {
		log.Warn("Setting dpdk interface mac address in vpp unsupported")
	} else if err != nil {
		return errors.Wrapf(err, "could not set dpdk interface %d mac address in vpp", swIfIndex)
	}
	return nil
}

func NewDPDKDriver(params *config.VppManagerParams, idx int) *DPDKDriver {
	d := &DPDKDriver{}
	d.name = NATIVE_DRIVER_DPDK
	d.attachedInterface = params.AttachedUplinksSpecs[idx]
	d.params = params
	return d
}
