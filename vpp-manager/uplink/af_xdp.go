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

	"github.com/projectcalico/vpp-dataplane/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	if d.conf.Mtu > maxAfXDPMTU {
		if warn {
			log.Warnf("MTU %d too large for AF_XDP (max 3072)", d.conf.Mtu)
		}
		return false
	}
	return false
}

func (d *AFXDPDriver) PreconfigureLinux() error {
	link, err := netlink.LinkByName(d.spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", d.spec.InterfaceName)
	}
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s promisc on", d.spec.InterfaceName)
	}
	err = utils.SetInterfaceRxQueues(d.spec.InterfaceName, d.spec.NumRxQueues)
	if err != nil {
		log.Errorf("Error setting link %s NumQueues to %d, using %d queues: %v", d.spec.InterfaceName, d.spec.NumRxQueues, d.conf.NumRxQueues, err)
		/* Try with linux NumRxQueues on error, otherwise af_xdp wont start */
		d.spec.NumRxQueues = d.conf.NumRxQueues
	}
	if d.conf.Mtu > maxAfXDPMTU {
		log.Infof("Reducing interface MTU to %d for AF_XDP", maxAfXDPMTU)
		err = netlink.LinkSetMTU(link, maxAfXDPMTU)
		if err != nil {
			return errors.Wrapf(err, "Error reducing MTU to %d", maxAfXDPMTU)
		}
		d.conf.Mtu = maxAfXDPMTU
	}
	if d.spec.Mtu > maxAfXDPMTU {
		log.Infof("Reducing user specified MTU to %d", maxAfXDPMTU)
		d.spec.Mtu = maxAfXDPMTU
	}
	return nil
}

func (d *AFXDPDriver) RestoreLinux(allInterfacesPhysical bool) {
	if !allInterfacesPhysical {
		err := d.moveInterfaceFromNS(d.spec.InterfaceName)
		if err != nil {
			log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}

	if !d.conf.IsUp {
		return
	}
	// Interface should pop back in root ns once vpp exits
	link, err := utils.SafeSetInterfaceUpByName(d.spec.InterfaceName)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.spec.InterfaceName, err)
		return
	}

	/* Restore XDP specific settings */
	log.Infof("Removing AF XDP conf")
	if !d.conf.PromiscOn {
		log.Infof("Setting promisc off")
		err = netlink.SetPromiscOff(link)
		if err != nil {
			log.Errorf("Error setting link %s promisc off %v", d.spec.InterfaceName, err)
		}
	}
	if d.conf.NumRxQueues != d.spec.NumRxQueues {
		log.Infof("Setting back %d queues", d.conf.NumRxQueues)
		err = utils.SetInterfaceRxQueues(d.spec.InterfaceName, d.conf.NumRxQueues)
		if err != nil {
			log.Errorf("Error setting link %s NumQueues to %d %v", d.spec.InterfaceName, d.conf.NumRxQueues, err)
		}
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AFXDPDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	err = d.moveInterfaceToNS(d.spec.InterfaceName, vppPid)
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

	err = vpp.SetInterfaceMacAddress(intf.SwIfIndex, d.conf.HardwareAddr)
	if err != nil {
		return errors.Wrap(err, "could not set af_xdp interface mac address in vpp")
	}
	d.spec.SwIfIndex = intf.SwIfIndex
	err = d.TagMainInterface(vpp, intf.SwIfIndex, d.spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewAFXDPDriver(params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *config.UplinkInterfaceSpec) *AFXDPDriver {
	d := &AFXDPDriver{}
	d.name = NATIVE_DRIVER_AF_XDP
	d.conf = conf
	d.params = params
	d.spec = spec
	return d
}
