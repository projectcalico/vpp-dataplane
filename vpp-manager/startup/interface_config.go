// Copyright (C) 2019 Cisco Systems Inc.
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

package startup

import (
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

func loadInterfaceConfigFromLinux(ifSpec config.UplinkInterfaceSpec) (*config.LinuxInterfaceState, error) {
	conf := config.LinuxInterfaceState{}
	link, err := netlink.LinkByName(ifSpec.InterfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find interface named %s", ifSpec.InterfaceName)
	}
	conf.IsUp = (link.Attrs().Flags & net.FlagUp) != 0
	if conf.IsUp {
		// Grab addresses and routes
		conf.Addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s addresses", ifSpec.InterfaceName)
		}

		conf.Routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s routes", ifSpec.InterfaceName)
		}
		conf.SortRoutes()
	}
	conf.HardwareAddr = link.Attrs().HardwareAddr
	conf.NodeIP4 = getNodeAddress(&conf, false /* isV6 */)
	conf.NodeIP6 = getNodeAddress(&conf, true /* isV6 */)
	conf.Hasv4 = (conf.NodeIP4 != "")
	conf.Hasv6 = (conf.NodeIP6 != "")
	if !conf.Hasv4 && !conf.Hasv6 {
		return nil, errors.Errorf("no address found for node")
	}

	conf.DoSwapDriver = false
	conf.PromiscOn = link.Attrs().Promisc == 1
	conf.NumTxQueues = link.Attrs().NumTxQueues
	conf.NumRxQueues = link.Attrs().NumRxQueues
	conf.Mtu = link.Attrs().MTU
	_, conf.IsTunTap = link.(*netlink.Tuntap)
	_, conf.IsVeth = link.(*netlink.Veth)

	pciID, err := utils.GetInterfacePciID(ifSpec.InterfaceName)
	// We allow PCI not to be found e.g for AF_PACKET
	if err != nil || pciID == "" {
		log.Infof("No pci device for interface %s", ifSpec.InterfaceName)
	} else {
		conf.PciID = pciID
		driver, err := utils.GetDriverNameFromPci(pciID)
		if err != nil {
			return nil, err
		}
		conf.Driver = driver
		if ifSpec.NewDriverName != "" && ifSpec.NewDriverName != conf.Driver {
			conf.DoSwapDriver = true
		}
	}
	conf.InterfaceName = ifSpec.InterfaceName
	return &conf, nil
}

func getNodeAddress(conf *config.LinuxInterfaceState, isV6 bool) string {
	for _, addr := range conf.Addresses {
		if vpplink.IsIP6(addr.IP) == isV6 {
			if !isV6 || !addr.IP.IsLinkLocalUnicast() {
				return addr.IPNet.String()
			}
		}
	}
	return ""
}
