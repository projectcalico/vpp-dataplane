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
)

type RDMADriver struct {
	UplinkDriverData
}

func (d *RDMADriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true

	ret = d.conf.Driver == config.DRIVER_MLX5_CORE
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.conf.Driver, config.DRIVER_MLX5_CORE)
	}
	supported = supported && ret

	return supported
}

func (d *RDMADriver) PreconfigureLinux() (err error) {
	d.removeLinuxIfConf(true /* down */)
	return nil
}

func (d *RDMADriver) RestoreLinux() {

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
	intf := types.RDMAInterface{
		GenericVppInterface: d.getGenericVppInterface(),
	}
	swIfIndex, err := vpp.CreateRDMA(&intf)

	if err != nil {
		return errors.Wrapf(err, "Error creating RDMA interface")
	}

	err = d.moveInterfaceToNS(d.params.MainInterface, vppPid)
	if err != nil {
		return errors.Wrap(err, "Moving uplink in NS failed")
	}

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
