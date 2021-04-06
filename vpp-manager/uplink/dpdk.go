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
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type DPDKDriver struct {
	UplinkDriverData
}

func (d *DPDKDriver) IsSupported(warn bool) bool {
	return true
}

func (d *DPDKDriver) PreconfigureLinux() (err error) {
	d.removeLinuxIfConf(true /* down */)
	finalDriver := d.conf.Driver
	if d.conf.DoSwapDriver {
		err = utils.SwapDriver(d.conf.PciId, d.params.NewDriverName, true)
		if err != nil {
			log.Warnf("Failed to swap driver to %s: %v", d.params.NewDriverName, err)
		}
		finalDriver = d.params.NewDriverName
	}
	if finalDriver == config.DRIVER_VFIO_PCI && d.params.AvailableHugePages == 0 {
		err := utils.SetVfioUnsafeiommu(false)
		if err != nil {
			return errors.Wrapf(err, "Virtio preconfigure error")
		}
	}
	return nil
}

func (d *DPDKDriver) GenerateVppConfigFile() error {
	template := d.params.ConfigTemplate
	template = strings.ReplaceAll(template, "__PCI_DEVICE_ID__", d.conf.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", d.params.MainInterface)
	dpdkPluginRegex := regexp.MustCompile(`plugin\s+dpdk_plugin.so\s+{\s+disable\s+}`)
	template = dpdkPluginRegex.ReplaceAllString(template, "plugin dpdk_plugin.so { enable }")

	dpdkStanzaRegex := regexp.MustCompile(`dpdk {[^}]+}`)
	if dpdkStanzaRegex.MatchString(template) {
		goto write
	}

	if d.params.AvailableHugePages > 0 {
		template = fmt.Sprintf("%s\ndpdk {\ndev %s { num-rx-queues %d num-rx-desc %d num-tx-desc %d } \n}\n", template, d.conf.PciId, d.params.NumRxQueues, d.params.RxQueueSize, d.params.TxQueueSize)
	} else {
		template = fmt.Sprintf("%s\ndpdk {\niova-mode va\nno-hugetlb\ndev %s { num-rx-queues %d num-rx-desc %d num-tx-desc %d } \n}\n", template, d.conf.PciId, d.params.NumRxQueues, d.params.RxQueueSize, d.params.TxQueueSize)

		// If no hugepages, also edit `buffers {}`
		buffersHeadRegex := regexp.MustCompile(`buffers\s+{`)
		buffersStanzaRegex := regexp.MustCompile(`buffers\s+{[^}]+}`)
		buffersNoHugeStanzaRegex := regexp.MustCompile(`buffers\s+{[^}]*no-hugetlb[^}]*}`)
		if buffersStanzaRegex.MatchString(template) {
			if !buffersNoHugeStanzaRegex.MatchString(template) {
				template = buffersHeadRegex.ReplaceAllString(template, "buffers {\nno-hugetlb")
				log.Infof("Found buffers")
			}
		} else {
			template = fmt.Sprintf("%s\nbuffers {\nno-hugetlb\n}", template)
		}
	}

write:
	return errors.Wrapf(
		ioutil.WriteFile(config.VppConfigFile, []byte(template+"\n"), 0644),
		"Error writing VPP configuration to %s",
		config.VppConfigFile,
	)
}

func (d *DPDKDriver) restoreInterfaceName() error {
	newName, err := utils.GetInterfaceNameFromPci(d.conf.PciId)
	if err != nil {
		return errors.Wrapf(err, "Error getting new if name for %s: %v", d.conf.PciId)
	}
	if newName == d.params.MainInterface {
		return nil
	}
	link, err := netlink.LinkByName(newName)
	if err != nil {
		return errors.Wrapf(err, "Error getting new link %s: %v", newName)
	}
	err = netlink.LinkSetName(link, d.params.MainInterface)
	if err != nil {
		return errors.Wrapf(err, "Error setting new if name for %s: %v", d.conf.PciId)
	}
	return nil
}

func (d *DPDKDriver) RestoreLinux() {
	if d.conf.PciId != "" && d.conf.Driver != "" {
		err := utils.SwapDriver(d.conf.PciId, d.conf.Driver, false)
		if err != nil {
			log.Warnf("Error swapping back driver to %s for %s: %v", d.conf.Driver, d.conf.PciId, err)
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

	if !d.conf.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := utils.SafeSetInterfaceUpByName(d.params.MainInterface)
	if err != nil {
		log.Warnf("Error seting %s up: %v", d.params.MainInterface, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *DPDKDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) error {
	/* Nothing to do VPP autocreates */
	return nil
}

func NewDPDKDriver(params *config.VppManagerParams, conf *config.InterfaceConfig) *DPDKDriver {
	d := &DPDKDriver{}
	d.name = NATIVE_DRIVER_DPDK
	d.conf = conf
	d.params = params
	return d
}
