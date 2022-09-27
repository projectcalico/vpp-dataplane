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
	"syscall"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	common_config "github.com/projectcalico/vpp-dataplane/common-config"
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
	spec   *common_config.UplinkInterfaceSpec
}

type UplinkDriver interface {
	PreconfigureLinux() error
	CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int) error
	RestoreLinux(allInterfacesPhysical bool)
	IsSupported(warn bool) bool
	GetName() string
	UpdateVppConfigFile(template string) string
}

func (d *UplinkDriverData) GetName() string {
	return d.name
}

func (d *UplinkDriverData) TagMainInterface(vpp *vpplink.VppLink, swIfIndex uint32, name string) (err error) {
	log.Infof("tagging interface [%d] with: %s", swIfIndex, "main-"+name)
	err = vpp.SetInterfaceTag(swIfIndex, "main-"+name)
	if err != nil {
		return err
	}
	return nil
}

func (d *UplinkDriverData) moveInterfaceFromNS(ifName string) error {
	ourNetns, err := ns.GetCurrentNS()
	if err != nil {
		return errors.Wrap(err, "cannot find our netns")
	}

	err = ns.WithNetNSPath(utils.GetnetnsPath(config.VppNetnsName), func(ns.NetNS) error {
		link, err := utils.SafeGetLink(ifName)
		if err != nil {
			return errors.Wrap(err, "cannot find uplink to move back to original netns")
		}
		err = netlink.LinkSetNsFd(link, int(ourNetns.Fd()))
		if err != nil {
			return errors.Wrap(err, "cannot move uplink back to original netns")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (d *UplinkDriverData) moveInterfaceToNS(ifName string, pid int) error {
	// Move interface to VPP namespace
	link, err := utils.SafeGetLink(ifName)
	if err != nil {
		return errors.Wrap(err, "cannot find uplink to move")
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
	link, err := netlink.LinkByName(d.spec.InterfaceName)
	if err != nil {
		log.Errorf("Error finding link %s: %s", d.spec.InterfaceName, err)
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
				log.Errorf("Error setting link %s down: %s", d.spec.InterfaceName, err)
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
		if err == syscall.EEXIST {
			log.Infof("restoring routes : %s already exists", route)
		} else if err != nil {
			log.Errorf("cannot add route %s back to %s : %+v", route, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}

}

func (d *UplinkDriverData) UpdateVppConfigFile(template string) string {
	return template
}

func (d *UplinkDriverData) getGenericVppInterface() types.GenericVppInterface {
	return types.GenericVppInterface{
		NumRxQueues:       d.spec.NumRxQueues,
		RxQueueSize:       d.spec.RxQueueSize,
		TxQueueSize:       d.spec.TxQueueSize,
		NumTxQueues:       d.spec.NumTxQueues,
		HardwareAddr:      &d.conf.HardwareAddr,
		HostInterfaceName: d.spec.InterfaceName,
	}
}

func SupportedUplinkDrivers(params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *common_config.UplinkInterfaceSpec) []UplinkDriver {
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

func NewUplinkDriver(name string, params *config.VppManagerParams, conf *config.LinuxInterfaceState, spec *common_config.UplinkInterfaceSpec) (d UplinkDriver) {
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
