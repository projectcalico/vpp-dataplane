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
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	vppmanagerparams "github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

const (
	minAfXDPKernelVersion = "5.4.0-0"
	maxAfXDPMTU           = 3072
)

type AFXDPDriver struct {
	UplinkDriverData
}

func (d *AFXDPDriver) IsSupported(warn bool) bool {
	minVersion, err := config.ParseKernelVersion(minAfXDPKernelVersion)
	if err != nil {
		d.log.Panicf("Error getting min kernel version %v", err)
	}
	if d.params.KernelVersion == nil {
		if warn {
			d.log.Warnf("Unknown current kernel version")
		}
		return false
	}
	if !d.params.KernelVersion.IsAtLeast(minVersion) {
		if warn {
			d.log.Warnf("Kernel %s doesn't support AF_XDP", d.params.KernelVersion)
		}
		return false
	}
	if d.intf.State.Mtu > maxAfXDPMTU {
		if warn {
			d.log.Warnf("MTU %d too large for AF_XDP (max 3072)", d.intf.State.Mtu)
		}
		return false
	}
	return false
}

func (d *AFXDPDriver) PreconfigureLinux() error {
	link, err := netlink.LinkByName(d.intf.Spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", d.intf.Spec.InterfaceName)
	}
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s promisc on", d.intf.Spec.InterfaceName)
	}
	err = config.SetInterfaceRxQueues(d.intf.Spec.InterfaceName, d.intf.Spec.NumRxQueues)
	if err != nil {
		d.log.Errorf("Error setting link %s NumQueues to %d, using %d queues: %v", d.intf.Spec.InterfaceName, d.intf.Spec.NumRxQueues, d.intf.State.NumRxQueues, err)
		/* Try with linux NumRxQueues on error, otherwise af_xdp wont start */
		d.intf.Spec.NumRxQueues = d.intf.State.NumRxQueues
	}
	if d.intf.State.Mtu > maxAfXDPMTU {
		d.log.Infof("Reducing interface MTU to %d for AF_XDP", maxAfXDPMTU)
		err = netlink.LinkSetMTU(link, maxAfXDPMTU)
		if err != nil {
			return errors.Wrapf(err, "Error reducing MTU to %d", maxAfXDPMTU)
		}
		d.intf.State.Mtu = maxAfXDPMTU
	}
	if d.intf.Spec.Mtu > maxAfXDPMTU {
		d.log.Infof("Reducing user specified MTU to %d", maxAfXDPMTU)
		d.intf.Spec.Mtu = maxAfXDPMTU
	}
	return nil
}

func (d *AFXDPDriver) RestoreLinux() {
	if !d.params.AllInterfacesPhysical() {
		err := d.moveInterfaceFromNS(d.intf.Spec.InterfaceName)
		if err != nil {
			d.log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}

	if !d.intf.State.IsUp {
		return
	}
	// Interface should pop back in root ns once vpp exits
	link, err := config.SafeSetInterfaceUpByName(d.intf.Spec.InterfaceName)
	if err != nil {
		d.log.Warnf("Error setting %s up: %v", d.intf.Spec.InterfaceName, err)
		return
	}

	/* Restore XDP specific settings */
	d.log.Infof("Removing AF XDP conf")
	if !d.intf.State.PromiscOn {
		d.log.Infof("Setting promisc off")
		err = netlink.SetPromiscOff(link)
		if err != nil {
			d.log.Errorf("Error setting link %s promisc off %v", d.intf.Spec.InterfaceName, err)
		}
	}
	if d.intf.State.NumRxQueues != d.intf.Spec.NumRxQueues {
		d.log.Infof("Setting back %d queues", d.intf.State.NumRxQueues)
		err = config.SetInterfaceRxQueues(d.intf.Spec.InterfaceName, d.intf.State.NumRxQueues)
		if err != nil {
			d.log.Errorf("Error setting link %s NumQueues to %d %v", d.intf.Spec.InterfaceName, d.intf.State.NumRxQueues, err)
		}
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AFXDPDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	err = d.moveInterfaceToNS(d.intf.Spec.InterfaceName, vppPid)
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
	d.log.Infof("Created AF_XDP interface %d", intf.SwIfIndex)

	err = vpp.SetInterfaceMacAddress(intf.SwIfIndex, d.intf.State.HardwareAddr)
	if err != nil {
		return errors.Wrap(err, "could not set af_xdp interface mac address in vpp")
	}
	d.intf.Spec.SwIfIndex = intf.SwIfIndex
	err = d.TagMainInterface(vpp, intf.SwIfIndex, d.intf.Spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewAFXDPDriver(params *vppmanagerparams.VppManagerParams,
	intf *vppmanagerparams.VppManagerInterface,
	log *logrus.Entry) *AFXDPDriver {
	return &AFXDPDriver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverAfXdp,
			params: params,
			intf:   intf,
			log:    log,
		},
	}
}
