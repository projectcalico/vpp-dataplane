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
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	minAfXDPKernelVersion = "5.4.0-0"
	maxAfXDPMTU           = 3072
)

type AFXDPDriver struct {
	UplinkDriverData
}

func (d *AFXDPDriver) IsSupported(warn bool) bool {
	minVersion, err := utils.ParseKernelVersion(minAfXDPKernelVersion)
	if err != nil {
		log.Panicf("Error getting min kernel version %v", err)
	}
	if d.params.KernelVersion == nil {
		if warn {
			log.Warnf("Unknown current kernel version")
		}
		return false
	}
	if !d.params.KernelVersion.IsAtLeast(minVersion) {
		if warn {
			log.Warnf("Kernel %s doesn't support AF_XDP", d.params.KernelVersion)
		}
		return false
	}
	if d.attachedInterface.LinuxConf.Mtu > maxAfXDPMTU {
		if warn {
			log.Warnf("MTU %d too large for AF_XDP (max 3072)", d.attachedInterface.LinuxConf.Mtu)
		}
		return false
	}
	return false
}

func (d *AFXDPDriver) PreconfigureLinux() error {
	link, err := netlink.LinkByName(d.attachedInterface.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", d.attachedInterface.InterfaceName)
	}
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s promisc on", d.attachedInterface.InterfaceName)
	}
	err = utils.SetInterfaceRxQueues(d.attachedInterface.InterfaceName, d.attachedInterface.NumRxQueues)
	if err != nil {
		log.Errorf("Error setting link %s NumQueues to %d, using %d queues: %v", d.attachedInterface.InterfaceName, d.attachedInterface.NumRxQueues, d.attachedInterface.LinuxConf.NumRxQueues, err)
		/* Try with linux NumRxQueues on error, otherwise af_xdp wont start */
		d.attachedInterface.NumRxQueues = d.attachedInterface.LinuxConf.NumRxQueues
	}
	if d.attachedInterface.LinuxConf.Mtu > maxAfXDPMTU {
		log.Infof("Reducing interface MTU to %d for AF_XDP", maxAfXDPMTU)
		err = netlink.LinkSetMTU(link, maxAfXDPMTU)
		if err != nil {
			return errors.Wrapf(err, "Error reducing MTU to %d", maxAfXDPMTU)
		}
		d.attachedInterface.LinuxConf.Mtu = maxAfXDPMTU
	}
	if d.attachedInterface.Mtu > maxAfXDPMTU {
		log.Infof("Reducing user specified MTU to %d", maxAfXDPMTU)
		d.attachedInterface.Mtu = maxAfXDPMTU
	}
	return nil
}

func (d *AFXDPDriver) RestoreLinux(allInterfacesPhysical bool) {
	if !allInterfacesPhysical {
		err := d.moveInterfaceFromNS(d.attachedInterface.InterfaceName)
		if err != nil {
			log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}

	if !d.attachedInterface.LinuxConf.IsUp {
		return
	}
	// Interface should pop back in root ns once vpp exits
	link, err := utils.SafeSetInterfaceUpByName(d.attachedInterface.InterfaceName)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.attachedInterface.InterfaceName, err)
		return
	}

	/* Restore XDP specific settings */
	log.Infof("Removing AF XDP conf")
	if !d.attachedInterface.LinuxConf.PromiscOn {
		log.Infof("Setting promisc off")
		err = netlink.SetPromiscOff(link)
		if err != nil {
			log.Errorf("Error setting link %s promisc off %v", d.attachedInterface.InterfaceName, err)
		}
	}
	if d.attachedInterface.LinuxConf.NumRxQueues != d.attachedInterface.NumRxQueues {
		log.Infof("Setting back %d queues", d.attachedInterface.LinuxConf.NumRxQueues)
		err = utils.SetInterfaceRxQueues(d.attachedInterface.InterfaceName, d.attachedInterface.LinuxConf.NumRxQueues)
		if err != nil {
			log.Errorf("Error setting link %s NumQueues to %d %v", d.attachedInterface.InterfaceName, d.attachedInterface.LinuxConf.NumRxQueues, err)
		}
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AFXDPDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	err = d.moveInterfaceToNS(d.attachedInterface.InterfaceName, vppPid)
	if err != nil {
		return errors.Wrap(err, "Moving uplink in NS failed")
	}

	intf := types.VppXDPInterface{
		GenericVppInterface: d.getGenericVppInterface(),
	}
	err = vpp.CreateAfXDP(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating AF_XDP interface")
	}
	log.Infof("Created AF_XDP interface %d", intf.SwIfIndex)

	err = vpp.SetInterfaceMacAddress(intf.SwIfIndex, d.attachedInterface.LinuxConf.HardwareAddr)
	if err != nil {
		return errors.Wrap(err, "could not set af_xdp interface mac address in vpp")
	}
	d.attachedInterface.SwIfIndex = intf.SwIfIndex
	err = d.TagMainInterface(vpp, intf.SwIfIndex, d.attachedInterface.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewAFXDPDriver(params *config.VppManagerParams, idx int) *AFXDPDriver {
	d := &AFXDPDriver{}
	d.name = NATIVE_DRIVER_AF_XDP
	d.attachedInterface = params.AttachedUplinksSpecs[idx]
	d.params = params
	return d
}
