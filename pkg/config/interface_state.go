// Copyright (C) 2022 Cisco Systems Inc.
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

package config

import (
	_ "embed"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
)

type LinuxInterfaceState struct {
	PciID  string
	Driver string
	IsUp   bool
	// addresses is the list of addresses present
	// on the netlink interface when the CNI starts up
	// keep in mind that addresses will contain the ipv6
	// link local of the old phy. Which might be different
	// from IPv6LinkLocal
	addresses []netlink.Addr
	// routes is the list of routes present on the netlink
	// interface when the CNI starts up
	routes        []netlink.Route
	Neighbors     []netlink.Neigh
	HardwareAddr  net.HardwareAddr
	PromiscOn     bool
	NumTxQueues   int
	NumRxQueues   int
	DoSwapDriver  bool
	Mtu           int
	InterfaceName string
	IsTunTap      bool
	IsVeth        bool
	// TapSwIfIndex is the sw_if_index of the tap interface
	// created in VPP for this interface
	TapSwIfIndex uint32
}

func (c *LinuxInterfaceState) GetNodeIP(ipf vpplink.IPFamily) *net.IPNet {
	for _, addr := range c.GetAddresses() {
		if vpplink.IPFamilyFromIP(addr.IP) == ipf {
			return addr.IPNet
		}
	}
	return nil
}

func (c *LinuxInterfaceState) AddressString() string {
	var str []string
	for _, addr := range c.addresses {
		str = append(str, addr.String())
	}
	return strings.Join(str, ",")
}

// getUplinkAddressWithMask adapts IPv6 non-link-local host prefixes from /128
// to /64 when TranslateUplinkAddrMaskTo64 is enabled.
func getUplinkAddressWithMask(addr *net.IPNet) *net.IPNet {
	if addr == nil || addr.IP == nil || addr.IP.To4() != nil || addr.IP.IsLinkLocalUnicast() {
		return addr
	}
	debugCfg := GetCalicoVppDebug()
	if debugCfg == nil || debugCfg.TranslateUplinkAddrMaskTo64 == nil || !*debugCfg.TranslateUplinkAddrMaskTo64 {
		return addr
	}
	ones, bits := addr.Mask.Size()
	if bits != 128 || ones != 128 {
		return addr
	}
	return &net.IPNet{
		IP:   addr.IP,
		Mask: net.CIDRMask(64, 128),
	}
}

func (c *LinuxInterfaceState) getAddresses(translateMask bool) []netlink.Addr {
	ret := make([]netlink.Addr, 0, len(c.addresses))
	for _, addr := range c.addresses {
		if addr.IP.IsLinkLocalUnicast() && isV6Cidr(addr.IPNet) {
			continue
		}
		if translateMask {
			addr.IPNet = getUplinkAddressWithMask(addr.IPNet)
		}
		ret = append(ret, addr)
	}
	return ret
}

// GetAddressesNoMaskTranslation returns non-link-local addresses exactly as
// discovered on Linux, without IPv6 /128 -> /64 adjustment.
func (c *LinuxInterfaceState) GetAddressesNoMaskTranslation() []netlink.Addr {
	return c.getAddresses(false /* translateMask */)
}

// GetAddresses returns non-link-local addresses, applying optional IPv6
// /128 -> /64 translation for non-link-local addresses.
func (c *LinuxInterfaceState) GetAddresses() []netlink.Addr {
	return c.getAddresses(true /* translateMask */)
}

func (c *LinuxInterfaceState) GetIPv6LinkLocal() *netlink.Addr {
	for _, addr := range c.addresses {
		if addr.IP.IsLinkLocalUnicast() && isV6Cidr(addr.IPNet) {
			return &addr
		}
	}
	return nil
}

func (c *LinuxInterfaceState) GetRoutes() []netlink.Route {
	ret := make([]netlink.Route, 0)
	for _, route := range c.routes {
		if route.Dst != nil && route.Dst.IP.IsLinkLocalUnicast() && isV6Cidr(route.Dst) {
			continue
		}
		ret = append(ret, route)
	}
	return ret
}

func (c *LinuxInterfaceState) GetAddressesAsIPNet() []*net.IPNet {
	ret := make([]*net.IPNet, 0)
	for _, addr := range c.GetAddresses() {
		ret = append(ret, addr.IPNet)
	}
	return ret
}

func (c *LinuxInterfaceState) HasAddr(addr net.IP) bool {
	for _, a := range c.addresses {
		if addr.Equal(a.IP) {
			return true
		}
	}
	return false
}

func (c *LinuxInterfaceState) RouteString() string {
	var str []string
	for _, route := range c.GetRoutes() {
		if route.Dst == nil {
			str = append(str, fmt.Sprintf("<Dst: nil (default), Ifindex: %d", route.LinkIndex))
			if route.Gw != nil {
				str = append(str, fmt.Sprintf("Gw: %s", route.Gw.String()))
			}
			if route.Src != nil {
				str = append(str, fmt.Sprintf("Src: %s", route.Src.String()))
			}
			str = append(str, ">")
		} else {
			str = append(str, route.String())
		}
	}
	return strings.Join(str, ", ")
}

// sortRoutes sorts the route slice by dependency order, so we can then add them
// in the order of the slice without issues
func (c *LinuxInterfaceState) sortRoutes() {
	sort.SliceStable(c.routes, func(i, j int) bool {
		// Directly connected routes go first
		if c.routes[i].Gw == nil {
			return true
		} else if c.routes[j].Gw == nil {
			return false
		}
		// Default routes go last
		if c.routes[i].Dst == nil {
			return false
		} else if c.routes[j].Dst == nil {
			return true
		}
		// Finally sort by decreasing prefix length
		iLen, _ := c.routes[i].Dst.Mask.Size()
		jLen, _ := c.routes[j].Dst.Mask.Size()
		return iLen > jLen
	})
}

func NewLinuxInterfaceState(ifSpec UplinkInterfaceSpec) (*LinuxInterfaceState, error) {
	ifState := LinuxInterfaceState{}
	link, err := netlink.LinkByName(ifSpec.InterfaceName)
	if err != nil {
		// attempt binding PCI devices to kernel
		bindErr := BindPCIDevicesToKernel()
		if bindErr != nil {
			return nil, errors.Wrapf(err, "cannot find interface named %s, cannot bind pci devices to kernel: %v", ifSpec.InterfaceName, bindErr)
		}
		link, err = netlink.LinkByName(ifSpec.InterfaceName)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot find interface named %s after binding devices to kernel", ifSpec.InterfaceName)
		}
	}
	ifState.IsUp = (link.Attrs().Flags & net.FlagUp) != 0
	if ifState.IsUp {
		// Grab addresses and routes
		ifState.addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s addresses", ifSpec.InterfaceName)
		}

		ifState.routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s routes", ifSpec.InterfaceName)
		}
		ifState.sortRoutes()
	}
	ifState.HardwareAddr = link.Attrs().HardwareAddr
	if ifState.GetNodeIP(vpplink.IPFamilyV4) == nil && ifState.GetNodeIP(vpplink.IPFamilyV6) == nil {
		return nil, errors.Errorf("no address found for node")
	}
	if ifSpec.IPFamilies.RequiresV4() && ifState.GetNodeIP(vpplink.IPFamilyV4) == nil {
		return nil, errors.Errorf("interface %s has no IPv4 address but ipFamilies=%q requires one",
			ifSpec.InterfaceName, ifSpec.IPFamilies)
	}
	if ifSpec.IPFamilies.RequiresV6() && ifState.GetNodeIP(vpplink.IPFamilyV6) == nil {
		return nil, errors.Errorf("interface %s has no IPv6 address but ipFamilies=%q requires one",
			ifSpec.InterfaceName, ifSpec.IPFamilies)
	}

	ifState.DoSwapDriver = false
	ifState.PromiscOn = link.Attrs().Promisc == 1
	ifState.NumTxQueues = link.Attrs().NumTxQueues
	ifState.NumRxQueues = link.Attrs().NumRxQueues
	ifState.Mtu = link.Attrs().MTU
	_, ifState.IsTunTap = link.(*netlink.Tuntap)
	_, ifState.IsVeth = link.(*netlink.Veth)

	pciID, err := GetInterfacePciID(ifSpec.InterfaceName)
	// We allow PCI not to be found e.g for AF_PACKET
	if err != nil || pciID == "" {
		log.Infof("No pci device for interface %s", ifSpec.InterfaceName)
	} else {
		ifState.PciID = pciID
		driver, err := GetDriverNameFromPci(pciID)
		if err != nil {
			return nil, err
		}
		ifState.Driver = driver
		if ifSpec.NewDriverName != "" && ifSpec.NewDriverName != ifState.Driver {
			ifState.DoSwapDriver = true
		}
	}
	ifState.InterfaceName = ifSpec.InterfaceName
	return &ifState, nil
}
