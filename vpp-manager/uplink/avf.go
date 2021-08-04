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

type AVFDriver struct {
	UplinkDriverData
	pfPCI string
	vfPCI string
}

func (d *AVFDriver) IsSupported(warn bool) (supported bool) {
	var ret bool
	supported = true
	ret = d.params.LoadedDrivers[config.DRIVER_VFIO_PCI]
	if !ret && warn {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
	supported = supported && ret

	ret = d.conf.Driver == config.DRIVER_I40E
	if !ret && warn {
		log.Warnf("Interface driver is <%s>, not %s", d.conf.Driver, config.DRIVER_I40E)
	}
	supported = supported && ret

	return supported
}

func (d *AVFDriver) PreconfigureLinux() (err error) {
	pciId, err := utils.GetInterfacePciId(d.params.MainInterface)
	if err != nil {
		return errors.Wrapf(err, "cannot get interface %s pciID", d.params.MainInterface)
	}

	numVFs, err := utils.GetInterfaceNumVFs(pciId)
	if err != nil {
		/* Most probably we were passed a VF */
		d.vfPCI = pciId
		d.pfPCI = ""
	} else {
		/* This is a PF */
		d.pfPCI = pciId
		if numVFs == 0 {
			log.Infof("Creating a VF for %s", d.params.MainInterface)
			err := utils.CreateInterfaceVF(pciId)
			if err != nil {
				return errors.Wrapf(err, "Couldnt create VF for %s", d.params.MainInterface)
			}

			/* Create a mac for the new VF */
			link, err := netlink.LinkByName(d.params.MainInterface)
			if err != nil {
				return errors.Wrapf(err, "Couldnt find Interface %s", d.params.MainInterface)
			}
			hardwareAddr := utils.CycleHardwareAddr(d.conf.HardwareAddr, 7)
			err = netlink.LinkSetVfHardwareAddr(link, 0 /* vf */, hardwareAddr)
			if err != nil {
				return errors.Wrapf(err, "Couldnt set VF 0 hwaddr %s", d.params.MainInterface)
			}
		}
		vfPCI, err := utils.GetInterfaceVFPciId(pciId)
		if err != nil {
			return errors.Wrapf(err, "Couldnt get VF pciID for %s", d.params.MainInterface)
		}
		d.vfPCI = vfPCI
	}

	if d.pfPCI != "" {
		err := utils.SetVFSpoofTrust(d.params.MainInterface, 0 /* vf */, false /* spoof */, true /* trust */)
		if err != nil {
			return errors.Wrapf(err, "Couldnt set VF spoof off trust on %s", d.params.MainInterface)
		}
	}

	driverName, err := utils.GetDriverNameFromPci(d.vfPCI)
	if err != nil {
		return errors.Wrapf(err, "Couldnt get VF driver Name for %s", d.vfPCI)
	}
	if driverName != config.DRIVER_VFIO_PCI {
		err := utils.BindVFtoDriver(d.vfPCI, config.DRIVER_VFIO_PCI)
		if err != nil {
			return errors.Wrapf(err, "Couldnt bind VF %s to vfio_pci", d.vfPCI)
		}
	}

	d.removeLinuxIfConf(true /* down */)

	return nil
}

func (d *AVFDriver) RestoreLinux() {
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

func (d *AVFDriver) CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) error {
	if d.pfPCI != "" {
		/* We were passed a PF, move it to vpp's NS so it doesn't
		   conflict with vpptap0 */
		err := d.moveInterfaceToNS(d.params.MainInterface, vppPid)
		if err != nil {
			return errors.Wrap(err, "Moving uplink in NS failed")
		}
	}

	intf := types.AVFInterface{
		GenericVppInterface: d.getGenericVppInterface(),
		PciId:               d.vfPCI,
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

	if swIfIndex != config.DataInterfaceSwIfIndex {
		return fmt.Errorf("Created AVF interface has wrong swIfIndex %d!", swIfIndex)
	}
	return nil
}

func NewAVFDriver(params *config.VppManagerParams, conf *config.InterfaceConfig) *AVFDriver {
	d := &AVFDriver{}
	d.name = NATIVE_DRIVER_AVF
	d.conf = conf
	d.params = params
	return d
}
