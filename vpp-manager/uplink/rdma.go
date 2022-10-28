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
	config "github.com/projectcalico/vpp-dataplane/config/config"
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

func (d *RDMADriver) RestoreLinux(allInterfacesPhysical bool) {
	if !allInterfacesPhysical {
		err := d.moveInterfaceFromNS(d.spec.InterfaceName)
		if err != nil {
			log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}
	if !d.conf.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := utils.SafeSetInterfaceUpByName(d.spec.InterfaceName)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.spec.InterfaceName, err)
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

	err = d.moveInterfaceToNS(d.spec.InterfaceName, vppPid)
	if err != nil {
		return errors.Wrap(err, "Moving uplink in NS failed")
	}

	log.Infof("Created RDMA interface %d", swIfIndex)

	d.spec.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewRDMADriver(params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *config.UplinkInterfaceSpec) *RDMADriver {
	d := &RDMADriver{}
	d.name = NATIVE_DRIVER_RDMA
	d.conf = conf
	d.params = params
	d.spec = spec
	return d
}
