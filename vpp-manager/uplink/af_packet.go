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
	"github.com/vishvananda/netlink"
)

type AFPacketDriver struct {
	UplinkDriverData
}

func (d *AFPacketDriver) IsSupported(warn bool) bool {
	return true
}

func (d *AFPacketDriver) PreconfigureLinux() error {
	link, err := netlink.LinkByName(d.spec.MainInterface)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", d.spec.MainInterface)
	}
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return errors.Wrapf(err, "Error set link %s promisc on", d.spec.MainInterface)
	}
	return nil
}

func (d *AFPacketDriver) RestoreLinux() {
	if !d.conf.IsUp {
		return
	}
	// Interface should pop back in root ns once vpp exits
	link, err := utils.SafeSetInterfaceUpByName(d.spec.MainInterface)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.spec.MainInterface, err)
		return
	}

	if !d.conf.PromiscOn {
		log.Infof("Setting promisc off")
		err = netlink.SetPromiscOff(link)
		if err != nil {
			log.Errorf("Error setting link %s promisc off %v", d.spec.MainInterface, err)
		}
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AFPacketDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) (swIfIndex uint32, err error) {
	err = d.moveInterfaceToNS(d.spec.MainInterface, vppPid)
	if err != nil {
		return 0, errors.Wrap(err, "Moving uplink in NS failed")
	}

	intf := types.AfPacketInterface{
		GenericVppInterface: d.getGenericVppInterface(),
	}
	swIfIndex, err = vpp.CreateAfPacket(&intf)
	if err != nil {
		return 0, errors.Wrapf(err, "Error creating AF_PACKET interface")
	}
	log.Infof("Created AF_PACKET interface %d", swIfIndex)

	if d.spec.Idx == 0 && swIfIndex != config.DataInterfaceSwIfIndex {
		return 0, fmt.Errorf("Created AF_PACKET interface has wrong swIfIndex %d!", swIfIndex)
	}

	return swIfIndex, nil
}

func NewAFPacketDriver(params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *config.InterfaceSpec) *AFPacketDriver {
	d := &AFPacketDriver{}
	d.name = NATIVE_DRIVER_AF_PACKET
	d.conf = conf
	d.params = params
	d.spec = spec
	return d
}
