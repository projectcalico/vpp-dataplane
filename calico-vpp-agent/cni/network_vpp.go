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

package cni

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type interfaceConfig struct {
	address net.IPNet
	gateway net.IP
}

func ifNameToSwIfIdx(name string) (uint32, error) {
	var ret uint32
	_, err := fmt.Sscanf(name, "vpp-tap-%u", &ret)
	return ret, err
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tap-%d", idx)
}

// writeProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
// This method was copied from cni-plugin/internal/pkg/utils/network_linux.go
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// configureContainerSysctls configures necessary sysctls required inside the container netns.
// This method was adapted from cni-plugin/internal/pkg/utils/network_linux.go
func (s *Server) configureContainerSysctls(allowIPForwarding, hasIPv4, hasIPv6 bool) error {
	ipFwd := "0"
	if allowIPForwarding {
		ipFwd = "1"
	}
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasIPv4 {
		s.log.Info("Configuring IPv4 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", ipFwd); err != nil {
			return err
		}
	}
	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasIPv6 {
		s.log.Info("Configuring IPv6 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", ipFwd); err != nil {
			return err
		}
	}
	return nil
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func (s *Server) SetupVppRoutes(swIfIndex uint32, ifConfigs []interfaceConfig) error {
	// Go through all the IPs and add routes for each IP in the result.
	for _, conf := range ifConfigs {
		ip := &net.IPNet{
			IP: conf.address.IP,
		}
		isIPv4 := ip.IP.To4() != nil
		if isIPv4 {
			ip.Mask = net.CIDRMask(32, 32)
		} else {
			ip.Mask = net.CIDRMask(128, 128)
		}
		route := types.Route{
			Dst: ip,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
				Gw:        ip.IP,
			}},
		}
		s.log.Infof("Adding vpp route %s", route.String())
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}

		hardwareAddr, err := net.ParseMAC(config.ContainerSideMacAddressString)
		if err != nil {
			return errors.Wrapf(err, "Unable to parse mac: %s", config.ContainerSideMacAddressString)
		}
		err = s.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           ip.IP,
			HardwareAddr: hardwareAddr,
			Flags:        types.IPNeighborStatic,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
	}
	return nil
}

func getPodv4IPNet(swIfIndex uint32) *net.IPNet {
	return &net.IPNet{
		IP:   net.IPv4(byte(169), byte(254), byte(swIfIndex>>8), byte(swIfIndex)),
		Mask: net.CIDRMask(32, 32),
	}
}

func getPodv6IPNet(swIfIndex uint32) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP{0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(swIfIndex >> 24), byte(swIfIndex >> 16), byte(swIfIndex >> 8), byte(swIfIndex)},
		Mask: net.CIDRMask(128, 128),
	}
}

func (s *Server) tapErrorCleanup(contTapName string, netns string, err error, msg string, args ...interface{}) error {
	s.log.Errorf("Error creating or configuring tap: %s %v", contTapName, err)
	delErr := s.DelVppInterface(&pb.DelRequest{
		InterfaceName: contTapName,
		Netns:         netns,
	})
	if delErr != nil {
		s.log.Errorf("Error deleting tap on error %s %v", contTapName, delErr)
	}
	return errors.Wrapf(err, msg, args...)
}

func getMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func getMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func (s *Server) getNamespaceSideGw(isv6 bool, swIfIndex uint32) (gwIp net.IP, err error) {
	if isv6 {
		// Retry several times as the LL can take a several micro/miliseconds to initialize and we may be too fast
		// after these sysctls
		for i := 0; i < 10; i++ {
			// No need to add a dummy next hop route as the host veth device will already have an IPv6
			// link local address that can be used as a next hop.
			// Just fetch the address of the host end of the veth and use it as the next hop.
			addresses, err := s.vpp.AddrList(swIfIndex, isv6)
			if err != nil {
				return nil, errors.Wrapf(err, "Error listing v6 addresses for the vpp side of the TAP")
			}
			for _, address := range addresses {
				return address.IPNet.IP, nil
			}
			s.log.Infof("No IPv6 set on interface, retrying..")
			time.Sleep(500 * time.Millisecond)
		}
		s.log.Errorf("No Ipv6 found for interface after 10 tries")
		return getPodv6IPNet(swIfIndex).IP, nil
	} else {
		return getPodv4IPNet(swIfIndex).IP, nil
	}
}

func (s *Server) announceLocalAddress(addr *net.IPNet, isWithdrawal bool) {
	s.routingServer.AnnounceLocalAddress(addr, isWithdrawal)
}

func (s *Server) configureNamespaceSideTap(
	args *pb.AddRequest,
	ifConfigs []interfaceConfig,
	routes []net.IPNet,
	swIfIndex uint32,
	contTapName string,
	contTapMac *string,
	doHostSideConf bool,
	hasv4 bool,
	hasv6 bool,
) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTap, err := netlink.LinkByName(contTapName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", contTapName, err)
		}

		// Fetch the MAC from the container tap. This is needed by Calico.
		*contTapMac = contTap.Attrs().HardwareAddr.String()
		s.log.Infof("tap[%d] has mac %s", swIfIndex, *contTapMac)

		/* We need to update dummy IPs in routes too
		   TODO: delete when switching to TUN */
		if !doHostSideConf && hasv4 {
			routes, err := netlink.RouteList(contTap, netlink.FAMILY_V4)
			if err != nil {
				s.log.Errorf("SR:Error getting v4 routes %v", err)
			}
			for _, r := range routes {
				err := netlink.RouteDel(&r)
				if err != nil {
					s.log.Errorf("SR:Error deleting v4 route %v : %v", r, err)
				}
			}
		}
		if !doHostSideConf && hasv6 {
			routes, err := netlink.RouteList(contTap, netlink.FAMILY_V6)
			if err != nil {
				s.log.Errorf("SR:Error getting v6 routes %v", err)
			}
			for _, r := range routes {
				err := netlink.RouteDel(&r)
				if err != nil {
					s.log.Errorf("SR:Error deleting v6 route %v : %v", r, err)
				}
			}
		}

		// Do the per-IP version set-up.  Add gateway routes etc.
		if hasv4 {
			// Add static neighbor entry for the VPP side of the tap
			hardwareAddr, err := net.ParseMAC(config.VppSideMacAddressString)
			if err != nil {
				return errors.Wrapf(err, "Unable to parse mac: %s", config.VppSideMacAddressString)
			}
			vppIPNet := getPodv4IPNet(swIfIndex)
			err = netlink.NeighAdd(&netlink.Neigh{
				LinkIndex:    contTap.Attrs().Index,
				Family:       netlink.FAMILY_V4,
				State:        netlink.NUD_PERMANENT,
				IP:           vppIPNet.IP,
				HardwareAddr: hardwareAddr,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add static neighbor entry in the container: %v", err)
			}

			s.log.Infof("Add tap[%d] linux%d route to %s", swIfIndex, contTap.Attrs().Index, vppIPNet.String())
			// Add a connected route to a dummy next hop so that a default route can be set
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTap.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       vppIPNet,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add route inside the container: %v", err)
			}
		}

		if hasv6 {
			if doHostSideConf {
				// Make sure ipv6 is enabled in the container/pod network namespace.
				// Without these sysctls enabled, interfaces will come up but they won't get a link local IPv6 address
				// which is required to add the default IPv6 route.
				if err = writeProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
					return fmt.Errorf("failed to set net.ipv6.conf.all.disable_ipv6=0: %s", err)
				}

				if err = writeProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
					return fmt.Errorf("failed to set net.ipv6.conf.default.disable_ipv6=0: %s", err)
				}

				if err = writeProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
					return fmt.Errorf("failed to set net.ipv6.conf.lo.disable_ipv6=0: %s", err)
				}
			}
			// FIXME : This isn't necessary if vpp can list link local ips
			// Add static neighbor entry for the VPP side of the tap
			hardwareAddr, err := net.ParseMAC(config.VppSideMacAddressString)
			if err != nil {
				return errors.Wrapf(err, "Unable to parse mac: %s", config.VppSideMacAddressString)
			}
			vppIPNet := getPodv6IPNet(swIfIndex)
			err = netlink.NeighAdd(&netlink.Neigh{
				LinkIndex:    contTap.Attrs().Index,
				Family:       netlink.FAMILY_V6,
				State:        netlink.NUD_PERMANENT,
				IP:           vppIPNet.IP,
				HardwareAddr: hardwareAddr,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add static neighbor entry in the container: %v", err)
			}

			s.log.Infof("Add tap[%d] linux%d route to %s", swIfIndex, contTap.Attrs().Index, vppIPNet.String())
			// Add a connected route to a dummy next hop so that a default route can be set
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTap.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       vppIPNet,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add route inside the container: %v", err)
			}
		}

		for _, route := range routes {
			isv6 := route.IP.To4() == nil
			if (isv6 && !hasv6) || (!isv6 && !hasv4) {
				s.log.Infof("Skipping tap[%d] route %s", swIfIndex, route.String())
				continue
			}
			gw, err := s.getNamespaceSideGw(isv6, swIfIndex)
			if err != nil {
				return errors.Wrapf(err, "failed to get Next hop for route")
			}
			s.log.Infof("Add tap[%d] linux%d route %s -> %s", swIfIndex, contTap.Attrs().Index, route.IP.String(), gw.String())
			err = ip.AddRoute(&route, gw, contTap)
			if err != nil {
				// TODO : in ipv6 '::' already exists
				s.log.Errorf("failed to add route %s -> %s : %v", route.IP.String(), gw.String(), err)
			}
		}

		if !doHostSideConf {
			return nil
		}

		// Now add the IPs to the container side of the tap.
		for _, conf := range ifConfigs {
			s.log.Infof("Add tap[%d] linux%d ip %s", swIfIndex, contTap.Attrs().Index, conf.address.String())
			err = netlink.AddrAdd(contTap, &netlink.Addr{IPNet: &conf.address})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %q: %v", contTap, err)
			}
			s.announceLocalAddress(&conf.address, false /* isWithdrawal */)
		}

		if err = s.configureContainerSysctls(args.GetSettings().GetAllowIpForwarding(), hasv4, hasv6); err != nil {
			return errors.Wrapf(err, "error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	}
}

// DoVppNetworking performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(args *pb.AddRequest, doHostSideConf bool) (ifName, contTapMac string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	contTapName := args.GetInterfaceName()
	netns := args.GetNetns()
	tapTag := netns + "-" + contTapName

	if args.GetDesiredHostInterfaceName() != "" {
		s.log.Warn("Desired host side interface name passed, this is not supported with VPP, ignoring it")
	}

	// Type conversion & validation
	var hasv4, hasv6 bool
	var ifConfigs []interfaceConfig
	for _, addr := range args.GetContainerIps() {
		address, network, err := net.ParseCIDR(addr.GetAddress())
		if err != nil {
			return "", "", fmt.Errorf("Cannot parse address: %s", addr.GetAddress())
		}
		if address.To4() == nil {
			hasv6 = true
		} else {
			hasv4 = true
		}
		network.IP = address
		gw := net.ParseIP(addr.GetGateway())
		if gw == nil {
			s.log.Infof("Cannot parse gateway: %s, ignoring anyway...", addr.GetGateway())
		}
		ifConfigs = append(ifConfigs, interfaceConfig{address: *network, gateway: gw})
	}

	var routes []net.IPNet
	for _, route := range args.GetContainerRoutes() {
		_, route, err := net.ParseCIDR(route)
		if err != nil {
			return "", "", errors.Wrapf(err, "Cannot parse container route %s", route.String())
		}
		routes = append(routes, *route)
	}

	vppSideMacAddress, err := net.ParseMAC(config.VppSideMacAddressString)
	if err != nil {
		return "", "", errors.Wrapf(err, "Unable to parse mac: %s", config.VppSideMacAddressString)
	}
	containerSideMacAddress, err := net.ParseMAC(config.ContainerSideMacAddressString)
	if err != nil {
		return "", "", errors.Wrapf(err, "Unable to parse mac: %s", config.ContainerSideMacAddressString)
	}

	// TODO: Clean up old tap if one is found with this tag
	tap := &types.TapV2{
		HostNamespace:  netns,
		HostIfName:     contTapName,
		Tag:            tapTag,
		MacAddress:     vppSideMacAddress,
		HostMacAddress: containerSideMacAddress,
		RxQueues:       config.TapRXQueues,
	}
	if config.TapGSOEnabled {
		tap.Flags |= types.TapFlagGSO | types.TapGROCoalesce
	}
	swIfIndex, err := s.vpp.CreateOrAttachTapV2(tap)
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error creating Tap")
	}
	s.log.Infof("created tap[%d]", swIfIndex)

	err = s.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "error setting new tap up")
	}

	err = s.vpp.SetInterfaceRxMode(swIfIndex, types.AllQueues, config.TapRxMode)
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "error SetInterfaceRxMode on data interface")
	}

	// configure vpp side TAP
	if hasv4 {
		s.log.Infof("Add vpp tap[%d] addr %s", swIfIndex, getPodv4IPNet(swIfIndex).String())
		err = s.vpp.AddInterfaceAddress(swIfIndex, getPodv4IPNet(swIfIndex))
		if err != nil {
			return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error adding ip4 tap address")
		}
	}
	if hasv6 {
		s.log.Infof("enable tap[%d] ipv6", swIfIndex)
		err = s.vpp.EnableInterfaceIP6(swIfIndex)
		if err != nil {
			return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error enabling ip6")
		}
		s.log.Infof("Add vpp tap[%d] addr %s", swIfIndex, getPodv6IPNet(swIfIndex).String())
		err = s.vpp.AddInterfaceAddress(swIfIndex, getPodv6IPNet(swIfIndex))
		if err != nil {
			return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error adding ip6 tap address")
		}
	}

	err = ns.WithNetNSPath(netns, s.configureNamespaceSideTap(args, ifConfigs, routes, swIfIndex, contTapName, &contTapMac, doHostSideConf, hasv4, hasv6))
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error creating or configuring tap")
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = s.SetupVppRoutes(swIfIndex, ifConfigs)
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "error adding vpp side routes for interface: %s", tapTag)
	}

	return swIfIdxToIfName(swIfIndex), contTapMac, err
}

func (s *Server) delVppInterfaceHandleRoutes(swIfIndex uint32, isIPv6 bool) error {
	// Delete neighbor entries. Is it really necessary?
	err, neighbors := s.vpp.GetInterfaceNeighbors(swIfIndex, isIPv6)
	if err != nil {
		return errors.Wrap(err, "GetInterfaceNeighbors errored")
	}
	for _, neighbor := range neighbors {
		err = s.vpp.DelNeighbor(&neighbor)
		if err != nil {
			s.log.Warnf("vpp del neighbor %v err: %v", neighbor, err)
		}
	}

	// Delete connected routes
	// TODO: Make TableID configurable?
	routes, err := s.vpp.GetRoutes(0, isIPv6)
	if err != nil {
		return errors.Wrap(err, "GetRoutes errored")
	}
	for _, route := range routes {
		// Our routes aren't multipath
		if len(route.Paths) != 1 {
			continue
		}
		// Filter routes we don't want to delete
		if route.Paths[0].SwIfIndex != swIfIndex {
			continue // Routes on other interfaces
		}
		maskSize, _ := route.Dst.Mask.Size()
		if isIPv6 {
			if maskSize != 128 {
				continue
			}
			if bytes.Equal(route.Dst.IP[0:2], []uint8{0xfe, 0x80}) {
				continue // Link locals
			}
		} else {
			if maskSize != 32 {
				continue
			}
			if bytes.Equal(route.Dst.IP[0:2], []uint8{169, 254}) {
				continue // Addresses configured on VPP side
			}
		}

		s.log.Warnf("vpp del route %s", route.String())
		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Warnf("vpp del route %s err: %v", route.String(), err)
		}
	}
	return nil
}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(args *pb.DelRequest) error {
	contIfName := args.GetInterfaceName()
	netns := args.GetNetns()
	// Only try to delete the device if a namespace was passed in.
	if netns == "" {
		s.log.Infof("no netns passed, skipping")
		return nil
	}

	devErr := ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
		dev, err := netlink.LinkByName(contIfName)
		if err != nil {
			return err
		}
		addresses, err := netlink.AddrList(dev, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, addr := range addresses {
			s.log.Infof("Found address %s on interface, scope %d", addr.IP.String(), addr.Scope)
			if addr.Scope == unix.RT_SCOPE_LINK {
				continue
			}
			s.announceLocalAddress(&net.IPNet{IP: addr.IP, Mask: addr.Mask}, true /* isWithdrawal */)
		}
		return nil
	})
	if devErr != nil {
		switch devErr.(type) {
		case netlink.LinkNotFoundError:
			s.log.Infof("Device to delete not found")
			return nil
		default:
			s.log.Warnf("error withdrawing interface addresses: %v", devErr)
			return errors.Wrap(devErr, "error withdrawing interface addresses")
		}

	}

	tag := netns + "-" + contIfName
	s.log.Infof("looking for tag %s", tag)
	err, swIfIndex := s.vpp.SearchInterfaceWithTag(tag)
	if err != nil {
		return errors.Wrapf(err, "error searching interface with tag %s", tag)
	}

	s.log.Infof("found matching VPP tap[%d]", swIfIndex)
	err = s.vpp.InterfaceAdminDown(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "InterfaceAdminDown errored")
	}

	err = s.delVppInterfaceHandleRoutes(swIfIndex, true /* isIp6 */)
	if err != nil {
		return errors.Wrap(err, "Error deleting ip6 routes")
	}
	err = s.delVppInterfaceHandleRoutes(swIfIndex, false /* isIp6 */)
	if err != nil {
		return errors.Wrap(err, "Error deleting ip4 routes")
	}

	// Delete tap
	err = s.vpp.DelTap(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "tap deletion failed")
	}
	s.log.Infof("deleted tap[%d]", swIfIndex)

	return nil
}
