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
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type AFXDPDriver struct {
	*UplinkDriverData
}

func (d *AFXDPDriver) PreconfigureLinux() error {
	link, err := netlink.LinkByName(d.params.MainInterface)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", d.params.MainInterface)
	}
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s promisc on", d.params.MainInterface)
	}
	err = utils.SetInterfaceRxQueues(d.params.MainInterface, d.params.NumRxQueues)
	if err != nil {
		return errors.Wrapf(err, "Error setting link %s NumQueues to %d", d.params.MainInterface, d.params.NumRxQueues)
	}
	return nil
}

func (d *AFXDPDriver) RestoreLinux() {
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

	/* Restore XDP specific settings */
	log.Infof("Removing AF XDP conf")
	if !d.conf.PromiscOn {
		log.Infof("Setting promisc off")
		err = netlink.SetPromiscOff(link)
		if err != nil {
			log.Errorf("Error setting link %s promisc off %v", d.params.MainInterface, err)
		}
	}
	if d.conf.NumRxQueues != d.params.NumRxQueues {
		log.Infof("Setting back %d queues", d.conf.NumRxQueues)
		err = utils.SetInterfaceRxQueues(d.params.MainInterface, d.conf.NumRxQueues)
		if err != nil {
			log.Errorf("Error setting link %s NumQueues to %d %v", d.params.MainInterface, d.conf.NumRxQueues, err)
		}
	}
	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AFXDPDriver) CreateMainVppInterface() (err error) {
	intf := types.VppXDPInterface{
		HostInterfaceName: d.params.MainInterface,
		RxQueueSize:       d.params.RxQueueSize,
		TxQueueSize:       d.params.TxQueueSize,
		NumRxQueues:       d.params.NumRxQueues,
	}
	err = d.vpp.CreateAfXDP(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating AF_XDP interface")
	}
	log.Infof("Created AF_XDP interface %d", intf.SwIfIndex)

	if intf.SwIfIndex != config.DataInterfaceSwIfIndex {
		return fmt.Errorf("Created AF_XDP interface has wrong swIfIndex %d!", intf.SwIfIndex)
	}
	return nil
}
