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

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	NATIVE_DRIVER_RDMA      = "rdma"
	NATIVE_DRIVER_VMXNET3   = "vmxnet3"
)

type UplinkDriverData struct {
	conf   *config.LinuxInterfaceState
	params *config.VppManagerParams
	name   string
	spec   *config.InterfaceSpec
}

type UplinkDriver interface {
	PreconfigureLinux() error
	CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) (uint32, error)
	RestoreLinux()
	IsSupported(warn bool) bool
	GetName() string
	UpdateVppConfigExecFile(template string) string
	UpdateVppConfigFile(template string) string
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
	link, err := netlink.LinkByName(d.spec.MainInterface)
	if err != nil {
		log.Errorf("Error finding link %s: %s", d.spec.MainInterface, err)
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
				log.Errorf("Error setting link %s down: %s", d.spec.MainInterface, err)
			}
		}
	}
}

func (d *UplinkDriverData) restoreLinuxIfConf(link netlink.Link) {
	err := netlink.LinkSetMTU(link, d.conf.Mtu)
	if err != nil {
		log.Errorf("Cannot restore mtu to %d: %v", d.conf.Mtu, err)
	}
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

func (d *UplinkDriverData) UpdateVppConfigFile(template string) string {
	return template
}

func (d *UplinkDriverData) UpdateVppConfigExecFile(template string) string {
	return template
}

func (d *UplinkDriverData) getGenericVppInterface() types.GenericVppInterface {
	return types.GenericVppInterface{
		NumRxQueues:       d.spec.NumRxQueues,
		RxQueueSize:       d.params.RxQueueSize,
		TxQueueSize:       d.params.TxQueueSize,
		NumTxQueues:       d.spec.NumTxQueues,
		HardwareAddr:      &d.conf.HardwareAddr,
		HostInterfaceName: d.spec.MainInterface,
	}
}

func SupportedUplinkDrivers(params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *config.InterfaceSpec) []UplinkDriver {
	lst := make([]UplinkDriver, 0)

	if d := NewVirtioDriver(params, conf, spec); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewAVFDriver(params, conf, spec); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewRDMADriver(params, conf, spec); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewVmxnet3Driver(params, conf, spec); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewAFXDPDriver(params, conf, spec); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	if d := NewAFPacketDriver(params, conf, spec); d.IsSupported(false /* warn */) {
		lst = append(lst, d)
	}
	return lst
}

func NewUplinkDriver(name string, params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *config.InterfaceSpec) (d UplinkDriver) {
	switch name {
	case NATIVE_DRIVER_RDMA:
		d = NewRDMADriver(params, conf, spec)
	case NATIVE_DRIVER_VMXNET3:
		d = NewVmxnet3Driver(params, conf, spec)
	case NATIVE_DRIVER_AF_PACKET:
		d = NewAFPacketDriver(params, conf, spec)
	case NATIVE_DRIVER_AF_XDP:
		d = NewAFXDPDriver(params, conf, spec)
	case NATIVE_DRIVER_VIRTIO:
		d = NewVirtioDriver(params, conf, spec)
	case NATIVE_DRIVER_AVF:
		d = NewAVFDriver(params, conf, spec)
	case NATIVE_DRIVER_DPDK:
		d = NewDPDKDriver(params, conf, spec)
	case NATIVE_DRIVER_NONE:
		fallthrough
	default:
		log.Warnf("Using default driver")
		d = NewDefaultDriver(params, conf, spec)
	}
	d.IsSupported(true /* warn */)
	return d
}
