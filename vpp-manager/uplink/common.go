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
)

type UplinkDriverData struct {
	conf   *config.InterfaceConfig
	params *config.VppManagerParams
	vpp    *vpplink.VppLink
}

type UplinkDriver interface {
	PreconfigureLinux() error
	CreateMainVppInterface() error
	RestoreLinux()
}

func (d *UplinkDriverData) restoreLinuxIfConf(link netlink.Link) {
	for _, addr := range d.conf.Addresses {
		if vpplink.IsIP6(addr.IP) && addr.IP.IsLinkLocalUnicast() {
			log.Infof("Skipping linklocal address %s", addr.String())
			continue
		}
		log.Infof("restoring address %s", addr.String())
		err := netlink.AddrAdd(link, &addr)
		if err != nil {
			log.Errorf("cannot add address %+v back to %s : %+v", addr, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}
	for _, route := range d.conf.Routes {
		if utils.RouteIsLinkLocalUnicast(&route) {
			log.Infof("Skipping linklocal route %s", route.String())
			continue
		}
		log.Infof("restoring route %s", route.String())
		route.LinkIndex = link.Attrs().Index
		err := netlink.RouteAdd(&route)
		if err != nil {
			log.Errorf("cannot add route %+v back to %s : %+v", route, link.Attrs().Name, err)
			// Keep going for the rest of the config
		}
	}

}

func NewUplinkDriver(params *config.VppManagerParams, conf *config.InterfaceConfig, vpp *vpplink.VppLink) UplinkDriver {
	d := &AFXDPDriver{}
	// TODO
	d.conf = conf
	d.params = params
	d.vpp = vpp
	return d
}
