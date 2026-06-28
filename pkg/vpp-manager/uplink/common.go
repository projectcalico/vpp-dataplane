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
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	vppmanagerparams "github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

const (
	NativeDriverNone     = "none"
	NativeDriverAfPacket = "af_packet"
	NativeDriverAfXdp    = "af_xdp"
	NativeDriverVirtio   = "virtio"
	NativeDriverDpdk     = "dpdk"
	NativeDriverRdma     = "rdma"
	NativeDriverVmxnet3  = "vmxnet3"
)

type UplinkDriverData struct {
	log    *logrus.Entry
	params *vppmanagerparams.VppManagerParams
	name   string
	intf   *vppmanagerparams.VppManagerInterface
}

func (d *UplinkDriverData) GetDefaultRxMode() types.RxMode { return types.AdaptativeRxMode }
func (d *UplinkDriverData) GetName() string                { return d.name }

func (d *UplinkDriverData) TagMainInterface(vpp *vpplink.VppLink, swIfIndex uint32, name string) (err error) {
	d.log.Infof("tagging interface [%d] with: %s", swIfIndex, "main-"+name)
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

	err = ns.WithNetNSPath(config.GetnetnsPath(config.VppNetnsName), func(ns.NetNS) error {
		link, err := config.SafeGetLink(ifName)
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
	link, err := config.SafeGetLink(ifName)
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
	link, err := netlink.LinkByName(d.intf.Spec.InterfaceName)
	if err != nil {
		d.log.Errorf("Error finding link %s: %s", d.intf.Spec.InterfaceName, err)
	} else {
		// Remove routes to not have them conflict with vpptap0
		for _, route := range d.intf.State.GetRoutes() {
			d.log.Infof("deleting Route %s", route.String())
			err := netlink.RouteDel(&route)
			if err != nil {
				d.log.Errorf("cannot delete route %+v: %+v", route, err)
			}
		}
		// Remove addresses to not have them conflict with vpptap0
		for _, addr := range d.intf.State.GetAddressesNoMaskTranslation() {
			err := netlink.AddrDel(link, &addr)
			if err != nil {
				d.log.Errorf("Error removing address %s from tap interface : %+v", addr, err)
			}
		}

		if d.intf.State.IsUp && setIfDown {
			err = netlink.LinkSetDown(link)
			if err != nil {
				// In case it still succeeded
				err2 := netlink.LinkSetUp(link)
				d.log.Errorf("Error setting link %s down: %s (err2 %s)", d.intf.Spec.InterfaceName, err, err2)
			}
		}
	}
}

func (d *UplinkDriverData) restoreLinuxIfConf(link netlink.Link) {
	err := netlink.LinkSetMTU(link, d.intf.State.Mtu)
	if err != nil {
		d.log.Errorf("Cannot restore mtu to %d: %v", d.intf.State.Mtu, err)
	}
	for _, addr := range d.intf.State.GetAddressesNoMaskTranslation() {
		d.log.Infof("restoring address %s", addr.String())
		err := netlink.AddrAdd(link, &addr)
		if err != nil {
			d.log.Errorf("cannot add address %+v back to %s : %+v", addr, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}
	for _, route := range d.intf.State.GetRoutes() {
		d.log.Infof("restoring route %s", route.String())
		route.LinkIndex = link.Attrs().Index
		err := netlink.RouteAdd(&route)
		if err == syscall.EEXIST {
			d.log.Infof("restoring routes : %s already exists", route)
		} else if err != nil {
			d.log.Errorf("cannot add route %s back to %s : %+v", route, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}

}

func (d *UplinkDriverData) UpdateVppConfigFile(template string) string {
	return template
}

func (d *UplinkDriverData) getGenericVppInterface() types.GenericVppInterface {
	return types.GenericVppInterface{
		NumRxQueues:       d.intf.Spec.NumRxQueues,
		RxQueueSize:       d.intf.Spec.RxQueueSize,
		TxQueueSize:       d.intf.Spec.TxQueueSize,
		NumTxQueues:       d.intf.Spec.NumTxQueues,
		HardwareAddr:      d.intf.State.HardwareAddr,
		HostInterfaceName: d.intf.Spec.InterfaceName,
	}
}

func NewUplinkDriver(name string, params *vppmanagerparams.VppManagerParams,
	intf *vppmanagerparams.VppManagerInterface,
	log *logrus.Entry,
) (d vppmanagerparams.UplinkDriver) {
	switch name {
	case NativeDriverRdma:
		d = NewRDMADriver(params, intf, log)
	case NativeDriverVmxnet3:
		d = NewVmxnet3Driver(params, intf, log)
	case NativeDriverAfPacket:
		d = NewAFPacketDriver(params, intf, log)
	case NativeDriverAfXdp:
		d = NewAFXDPDriver(params, intf, log)
	case NativeDriverVirtio:
		d = NewVirtioDriver(params, intf, log)
	case NativeDriverDpdk:
		d = NewDPDKDriver(params, intf, log)
	case NativeDriverNone:
		fallthrough
	default:
		log.Warnf("Using default driver")
		d = NewDefaultDriver(params, intf, log)
	}
	d.IsSupported(true /* warn */)
	return d
}
