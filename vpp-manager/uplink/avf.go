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

type AVFDriver struct {
	UplinkDriverData
	pfPCI string
	vfPCI string
}

func (d *AVFDriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true
	ret = d.params.LoadedDrivers[config.DriverVfioPci]
	if !ret && warn {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
	supported = supported && ret

	ret = d.conf.Driver == config.DriverI40E || d.conf.Driver == config.DriverICE
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.conf.Driver, config.DriverI40E)
	}
	supported = supported && ret

	return supported
}

func (d *AVFDriver) PreconfigureLinux() (err error) {
	pciID, err := utils.GetInterfacePciID(d.intf.Spec.InterfaceName)
	if err != nil {
		return errors.Wrapf(err, "cannot get interface %s pciID", d.intf.Spec.InterfaceName)
	}

	numVFs, err := utils.GetInterfaceNumVFs(pciID)
	if err != nil {
		/* Most probably we were passed a VF */
		d.vfPCI = pciID
		d.pfPCI = ""
	} else {
		/* This is a PF */
		d.pfPCI = pciID
		if numVFs == 0 {
			log.Infof("Creating a VF for %s", d.intf.Spec.InterfaceName)
			err := utils.CreateInterfaceVF(pciID)
			if err != nil {
				return errors.Wrapf(err, "Couldnt create VF for %s", d.intf.Spec.InterfaceName)
			}

			/* Create a mac for the new VF */
			link, err := netlink.LinkByName(d.intf.Spec.InterfaceName)
			if err != nil {
				return errors.Wrapf(err, "Couldnt find Interface %s", d.intf.Spec.InterfaceName)
			}
			hardwareAddr := utils.CycleHardwareAddr(d.conf.HardwareAddr, 7)
			err = netlink.LinkSetVfHardwareAddr(link, 0 /* vf */, hardwareAddr)
			if err != nil {
				return errors.Wrapf(err, "Couldnt set VF 0 hwaddr %s", d.intf.Spec.InterfaceName)
			}
		}
		vfPCI, err := utils.GetInterfaceVFPciID(pciID)
		if err != nil {
			return errors.Wrapf(err, "Couldnt get VF pciID for %s", d.intf.Spec.InterfaceName)
		}
		d.vfPCI = vfPCI
	}

	if d.pfPCI != "" {
		err := utils.SetVFSpoofTrust(d.intf.Spec.InterfaceName, 0 /* vf */, false /* spoof */, true /* trust */)
		if err != nil {
			return errors.Wrapf(err, "Couldnt set VF spoof off trust on %s", d.intf.Spec.InterfaceName)
		}
	}

	driverName, err := utils.GetDriverNameFromPci(d.vfPCI)
	if err != nil {
		return errors.Wrapf(err, "Couldnt get VF driver Name for %s", d.vfPCI)
	}
	if driverName != config.DriverVfioPci {
		err := utils.BindVFtoDriver(d.vfPCI, config.DriverVfioPci)
		if err != nil {
			return errors.Wrapf(err, "Couldnt bind VF %s to vfio_pci", d.vfPCI)
		}
	}

	d.removeLinuxIfConf(true /* down */)

	return nil
}

func (d *AVFDriver) RestoreLinux() {
	if !d.params.AllInterfacesPhysical() {
		if d.pfPCI != "" {
			err := d.moveInterfaceFromNS(d.intf.Spec.InterfaceName)
			if err != nil {
				log.Warnf("Moving uplink back from NS failed %s", err)
			}
		}
	}
	if !d.conf.IsUp {
		return
	}
	// This assumes the link has kept the same name after the rebind.
	// It should be always true on systemd based distros
	link, err := utils.SafeSetInterfaceUpByName(d.intf.Spec.InterfaceName)
	if err != nil {
		log.Warnf("Error setting %s up: %v", d.intf.Spec.InterfaceName, err)
		return
	}

	// Re-add all adresses and routes
	d.restoreLinuxIfConf(link)
}

func (d *AVFDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) (err error) {
	if d.pfPCI != "" {
		/* We were passed a PF, move it to vpp's NS so it doesn't
		   conflict with vpptap0 */
		err := d.moveInterfaceToNS(d.intf.Spec.InterfaceName, vppPid)
		if err != nil {
			return errors.Wrap(err, "Moving uplink in NS failed")
		}
	}

	intf := types.AVFInterface{
		GenericVppInterface: d.getGenericVppInterface(),
		PciID:               d.vfPCI,
	}
	swIfIndex, err := vpp.CreateAVF(&intf)
	if err != nil {
		return errors.Wrapf(err, "Error creating AVF interface")
	}
	log.Infof("Created AVF interface %d", swIfIndex)

	err = vpp.SetPromiscOn(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error setting AVF promisc on")
	}

	d.intf.Spec.SwIfIndex = swIfIndex
	err = d.TagMainInterface(vpp, swIfIndex, d.intf.Spec.InterfaceName)
	if err != nil {
		return err
	}
	return nil
}

func NewAVFDriver(params *config.VppManagerParams, intf *config.VppManagerInterface) *AVFDriver {
	return &AVFDriver{
		UplinkDriverData: UplinkDriverData{
			name:   NativeDriverAvf,
			params: params,
			intf:   intf,
		},
	}
}
