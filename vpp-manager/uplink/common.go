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
	"io/ioutil"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	NATIVE_DRIVER_NONE      = "none"
	NATIVE_DRIVER_AF_PACKET = "af_packet"
	NATIVE_DRIVER_AF_XDP    = "af_xdp"
	NATIVE_DRIVER_VIRTIO    = "virtio"
	NATIVE_DRIVER_AVF       = "avf"
	NATIVE_DRIVER_DPDK      = "dpdk"
)

type UplinkDriverData struct {
	conf   *config.InterfaceConfig
	params *config.VppManagerParams
	name   string
}

type UplinkDriver interface {
	PreconfigureLinux() error
	CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) error
	RestoreLinux()
	IsSupported(warn bool) bool
	GetName() string
	GenerateVppConfigExecFile() error
	GenerateVppConfigFile() error
}

func (d *UplinkDriverData) GetName() string {
	return d.name
}

func (d *UplinkDriverData) moveInterfaceToNS(ifName string, pid int) error {
	// Move interface to VPP namespace
	link, err := utils.SafeGetLink(ifName)
	if err != nil {
		return errors.Wrap(err, "cannot find uplink for af_xdp")
	}
	err = netlink.LinkSetNsPid(link, pid)
	if err != nil {
		return errors.Wrap(err, "cannot move uplink to vpp netns")
	}
	err = ns.WithNetNSPath(fmt.Sprintf("/proc/%d/ns/net", pid), func(ns.NetNS) error {
		return netlink.LinkSetUp(link)
	})
	if err != nil {
		return errors.Wrap(err, "cannot set uplink up in vpp ns")
	}
	return nil
}

func (d *UplinkDriverData) removeLinuxIfConf(setIfDown bool) {
	link, err := netlink.LinkByName(d.params.MainInterface)
	if err != nil {
		log.Errorf("Error finding link %s: %s", d.params.MainInterface, err)
	} else {
		// Remove routes to not have them conflict with vpptap0
		for _, route := range d.conf.Routes {
			log.Infof("deleting Route %s", route.String())
			err := netlink.RouteDel(&route)
			if err != nil {
				log.Errorf("cannot delete route %+v: %+v", route, err)
			}
		}
		// Remove addresses to not have them conflict with vpptap0
		for _, addr := range d.conf.Addresses {
			err := netlink.AddrDel(link, &addr)
			if err != nil {
				log.Errorf("Error removing address %s from tap interface : %+v", addr, err)
			}
		}

		if d.conf.IsUp && setIfDown {
			err = netlink.LinkSetDown(link)
			if err != nil {
				// In case it still succeeded
				netlink.LinkSetUp(link)
				log.Errorf("Error setting link %s down: %s", d.params.MainInterface, err)
			}
		}
	}
}

func (d *UplinkDriverData) restoreLinuxIfConf(link netlink.Link) {
	for _, addr := range d.conf.Addresses {
		log.Infof("restoring address %s", addr.String())
		err := netlink.AddrAdd(link, &addr)
		if err != nil {
			log.Errorf("cannot add address %+v back to %s : %+v", addr, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}
	for _, route := range d.conf.Routes {
		log.Infof("restoring route %s", route.String())
		route.LinkIndex = link.Attrs().Index
		err := netlink.RouteAdd(&route)
		if err != nil {
			log.Errorf("cannot add route %+v back to %s : %+v", route, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}

}

func (d *UplinkDriverData) GenerateVppConfigExecFile() error {
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(d.params.ConfigExecTemplate, "__PCI_DEVICE_ID__", d.conf.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", d.params.MainInterface)
	err := errors.Wrapf(
		ioutil.WriteFile(config.VppConfigExecFile, []byte(template+"\n"), 0744),
		"Error writing VPP Exec configuration to %s",
		config.VppConfigExecFile,
	)
	return err
}

func (d *UplinkDriverData) GenerateVppConfigFile() error {
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(d.params.ConfigTemplate, "__PCI_DEVICE_ID__", d.conf.PciId)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", d.params.MainInterface)
	return errors.Wrapf(
		ioutil.WriteFile(config.VppConfigFile, []byte(template+"\n"), 0644),
		"Error writing VPP configuration to %s",
		config.VppConfigFile,
	)
}

func SupportedUplinkDrivers(params *config.VppManagerParams, conf *config.InterfaceConfig) []UplinkDriver {
	lst := make([]UplinkDriver, 0)

	if d := NewVirtioDriver(params, conf); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewAVFDriver(params, conf); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewAFXDPDriver(params, conf); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewAFPacketDriver(params, conf); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	return lst
}

func NewUplinkDriver(name string, params *config.VppManagerParams, conf *config.InterfaceConfig) (d UplinkDriver) {
	switch name {
	case NATIVE_DRIVER_AF_PACKET:
		d = NewAFPacketDriver(params, conf)
	case NATIVE_DRIVER_AF_XDP:
		d = NewAFXDPDriver(params, conf)
	case NATIVE_DRIVER_VIRTIO:
		d = NewVirtioDriver(params, conf)
	case NATIVE_DRIVER_AVF:
		d = NewAVFDriver(params, conf)
	case NATIVE_DRIVER_DPDK:
		d = NewDPDKDriver(params, conf)
	case NATIVE_DRIVER_NONE:
		fallthrough
	default:
		log.Warnf("Using default driver")
		d = NewDefaultDriver(params, conf)
	}
	d.IsSupported(true /* warn */)
	return d
}
