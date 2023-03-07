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
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/af_packet"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type AFPacketDriver struct {
	UplinkDriverData
}

func (d *AFPacketDriver) IsSupported(warn bool) bool {
	return true
}

// We prefer defaulting to adaptive, but af_packet only supports interrupt or polling
func (d *AFPacketDriver) GetDefaultRxMode() types.RxMode { return types.InterruptRxMode }

func (d *AFPacketDriver) PreconfigureLinux() error {
	link, err := netlink.LinkByName(d.spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "Error finding link %s", d.spec.InterfaceName)
	}
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return errors.Wrapf(err, "Error set link %s promisc on", d.spec.InterfaceName)
	}
	return nil
}

func (d *AFPacketDriver) RestoreLinux(allInterfacesPhysical bool) {
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

	if !d.conf.PromiscOn {
		log.Infof("Setting promisc off")
		err = netlink.SetPromiscOff(link)
		if err != nil {
			log.Errorf("Error setting link %s promisc off %v", d.spec.InterfaceName, err)
		}
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AFPacketDriver) fetchBooleanAnnotation(annotation string, defaultValue bool, uplinkSpec *config.UplinkInterfaceSpec) bool {
	spec, found := uplinkSpec.Annotations[annotation]
	if !found {
		return defaultValue
	}
	b, err := strconv.ParseBool(spec)
	if err != nil {
		log.WithError(err).Errorf("Error parsing annotation %s '%s'", annotation, spec)
		return defaultValue
	}
	return b
}

func (d *AFPacketDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	err = d.moveInterfaceToNS(d.spec.InterfaceName, vppPid)
	if err != nil {
		return errors.Wrap(err, "Moving uplink in NS failed")
	}

	intf := types.AfPacketInterface{GenericVppInterface: d.getGenericVppInterface()}
	if *config.GetCalicoVppDebug().GSOEnabled {
		intf.Flags |= af_packet.AF_PACKET_API_FLAG_CKSUM_GSO
	}
	if d.fetchBooleanAnnotation("AfPacketQdiscBypass", false /* default */, uplinkSpec) {
		intf.Flags |= af_packet.AF_PACKET_API_FLAG_QDISC_BYPASS
	}
	if !d.fetchBooleanAnnotation("AfPacketUseV3", false /* default */, uplinkSpec) {
		intf.Flags |= af_packet.AF_PACKET_API_FLAG_VERSION_2
	}
	swIfIndex, err := vpp.CreateAfPacket(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating AF_PACKET interface")
	}
	log.Infof("Created AF_PACKET interface %d", swIfIndex)

	d.spec.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewAFPacketDriver(params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *config.UplinkInterfaceSpec) *AFPacketDriver {
	d := &AFPacketDriver{}
	d.name = NATIVE_DRIVER_AF_PACKET
	d.conf = conf
	d.params = params
	d.spec = spec
	return d
}
