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

type AFPacketDriver struct {
	UplinkDriverData
}

func (d *AFPacketDriver) IsSupported(warn bool) bool {
	return true
}

func (d *AFPacketDriver) PreconfigureLinux() error {
	d.removeLinuxIfConf(true /* down */)
	return nil
}

func (d *AFPacketDriver) RestoreLinux() {
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

func (d *AFPacketDriver) CreateMainVppInterface(vpp *vpplink.VppLink) (err error) {
	swIfIndex, err := vpp.CreateAfPacket(d.params.MainInterface, &d.conf.HardwareAddr)
	if err != nil {
		return errors.Wrapf(err, "Error creating AF_PACKET interface")
	}
	log.Infof("Created AF_PACKET interface %d", swIfIndex)

	if swIfIndex != config.DataInterfaceSwIfIndex {
		return fmt.Errorf("Created AF_PACKET interface has wrong swIfIndex %d!", swIfIndex)
	}
	return nil
}

func NewAFPacketDriver(params *config.VppManagerParams, conf *config.InterfaceConfig) *AFPacketDriver {
	d := &AFPacketDriver{}
	d.name = NATIVE_DRIVER_AF_PACKET
	d.conf = conf
	d.params = params
	return d
}
