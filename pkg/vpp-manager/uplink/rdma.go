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

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	vppmanagerparams "github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

type RDMADriver struct {
	UplinkDriverData
}

func (d *RDMADriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true

	ret = d.intf.State.Driver == config.DriverMLX5Core
	if !ret && warn {
		d.log.Warnf("Interface driver is <%s>, not %s", d.intf.State.Driver, config.DriverMLX5Core)
	}
	supported = supported && ret

	return supported
}

func (d *RDMADriver) PreconfigureLinux() (err error) {
	d.removeLinuxIfConf(true /* down */)
	return nil
}

func (d *RDMADriver) RestoreLinux() {
	if !d.params.AllInterfacesPhysical() {
		err := d.moveInterfaceFromNS(d.intf.Spec.InterfaceName)
		if err != nil {
			d.log.Warnf("Moving uplink back from NS failed %s", err)
		}
	}
	if !d.intf.State.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := config.SafeSetInterfaceUpByName(d.intf.Spec.InterfaceName)
	if err != nil {
		d.log.Warnf("Error setting %s up: %v", d.intf.Spec.InterfaceName, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *RDMADriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	intf := types.RDMAInterface{
		GenericVppInterface: d.getGenericVppInterface(),
	}
	swIfIndex, err := vpp.CreateRDMA(&intf)

	if err != nil {
		return errors.Wrapf(err, "Error creating RDMA interface")
	}

	err = d.moveInterfaceToNS(d.intf.Spec.InterfaceName, vppPid)
	if err != nil {
		return errors.Wrap(err, "Moving uplink in NS failed")
	}

	d.log.Infof("Created RDMA interface %d", swIfIndex)

	d.intf.Spec.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.intf.Spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewRDMADriver(params *vppmanagerparams.VppManagerParams,
	intf *vppmanagerparams.VppManagerInterface,
	log *logrus.Entry,
) *RDMADriver {
	return &RDMADriver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverRdma,
			params: params,
			intf:   intf,
			log:    log,
		},
	}
}
