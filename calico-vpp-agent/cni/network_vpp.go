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

	"github.com/projectcalico/vpp-dataplane/vpplink/types"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type InterfaceAddress struct {
	IPNet   *net.IPNet
	gateway net.IP
}

func (r *InterfaceAddress) String() string {
	return fmt.Sprintf("%s (gw %s)", r.IPNet.String(), r.gateway.String())
}

type InterfaceConf struct {
	addresses         []InterfaceAddress
	routes            []*net.IPNet
	Hasv6             bool
	Hasv4             bool
	NeedSnat          bool
	AllowIpForwarding bool
}

func ifNameToSwIfIdx(name string) (uint32, error) {
	var ret uint32
	_, err := fmt.Sscanf(name, "vpp-tun-%u", &ret)
	return ret, err
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
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
func (s *Server) SetupVppRoutes(swIfIndex uint32, conf *InterfaceConf) error {
	// Go through all the IPs and add routes for each IP in the result.
	for _, address := range conf.addresses {
		route := types.Route{
			Dst: address.IPNet,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		}
		s.log.Infof("Adding vpp route %s", route.String())
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}
	}
	return nil
}

func (s *Server) tunErrorCleanup(contTunName string, netns string, err error, msg string, args ...interface{}) error {
	s.log.Errorf("Error creating or configuring tun: %s", err)
	delErr := s.DelVppInterface(&pb.DelRequest{
		InterfaceName: contTunName,
		Netns:         netns,
	})
	if delErr != nil {
		s.log.Errorf("Error deleting tun on error %s %v", contTunName, delErr)
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

func (s *Server) announceLocalAddress(addr *net.IPNet, isWithdrawal bool) {
	s.routingServer.AnnounceLocalAddress(addr, isWithdrawal)
}

func (s *Server) configureNamespaceSideTun(conf *InterfaceConf, swIfIndex uint32, contTunName string) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTun, err := netlink.LinkByName(contTunName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", contTunName, err)
		}

		// Do the per-IP version set-up.  Add gateway routes etc.
		if conf.Hasv6 {
			s.log.Infof("tun %d in NS has v6", swIfIndex)
			// Make sure ipv6 is enabled in the container/pod network namespace.
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

		for _, route := range conf.routes {
			isV6 := route.IP.To4() == nil
			if (isV6 && !conf.Hasv6) || (!isV6 && !conf.Hasv4) {
				s.log.Infof("Skipping tun[%d] route for %s", swIfIndex, route.String())
				continue
			}
			s.log.Infof("Add tun[%d] linux%d route for %s", swIfIndex, contTun.Attrs().Index, route.String())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTun.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       route,
			})
			if err != nil {
				// TODO : in ipv6 '::' already exists
				s.log.Errorf("Error adding tun[%d] route for %s", swIfIndex, route.String())
			}
		}

		// Now add the IPs to the container side of the tun.
		for _, address := range conf.addresses {
			s.log.Infof("Add tun[%d] linux%d ip %s", swIfIndex, contTun.Attrs().Index, address.String())
			err = netlink.AddrAdd(contTun, &netlink.Addr{IPNet: address.IPNet})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %s: %v", contTun.Attrs().Name, err)
			}
			s.announceLocalAddress(address.IPNet, false /* isWithdrawal */)
		}

		if err = s.configureContainerSysctls(conf.AllowIpForwarding, conf.Hasv4, conf.Hasv6); err != nil {
			return errors.Wrapf(err, "error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	}
}

func (s *Server) ParseInterfaceAddRequest(args *pb.AddRequest) (conf *InterfaceConf, err error) {
	conf = &InterfaceConf{}
	conf.Hasv4 = false
	conf.Hasv6 = false
	conf.NeedSnat = false
	conf.routes = make([]*net.IPNet, 0)
	conf.addresses = make([]InterfaceAddress, 0)
	conf.AllowIpForwarding = args.GetSettings().GetAllowIpForwarding()
	for _, containerIP := range args.GetContainerIps() {
		address, _, err := net.ParseCIDR(containerIP.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("Cannot parse address: %s", containerIP.GetAddress())
		}
		if address.To4() == nil {
			conf.Hasv6 = true
		} else {
			conf.Hasv4 = true
		}
		// We ignore the prefix len set on the address,
		// for a tun it doesn't make sense
		network := &net.IPNet{
			IP:   address,
			Mask: getMaxCIDRMask(address),
		}
		gw := net.ParseIP(containerIP.GetGateway())
		if gw == nil {
			s.log.Infof("Cannot parse gateway: %s, ignoring anyway...", containerIP.GetGateway())
		}
		conf.addresses = append(conf.addresses, InterfaceAddress{IPNet: network, gateway: gw})
		conf.NeedSnat = conf.NeedSnat || s.IPNetNeedsSNAT(network)
	}
	for _, route := range args.GetContainerRoutes() {
		_, route, err := net.ParseCIDR(route)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse container route %s", route.String())
		}
		conf.routes = append(conf.routes, route)
	}
	return conf, nil
}

// DoVppNetworking performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(args *pb.AddRequest, doHostSideConf bool) (ifName, contTunMac string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	contTunName := args.GetInterfaceName()
	netns := args.GetNetns()
	tunTag := netns + "-" + contTunName

	if args.GetDesiredHostInterfaceName() != "" {
		s.log.Warn("Desired host side interface name passed, this is not supported with VPP, ignoring it")
	}

	// Type conversion & validation
	interfaceConfig, err := s.ParseInterfaceAddRequest(args)
	if err != nil {
		return "", "", errors.Wrapf(err, "Error parsing Interface Add request")
	}

	s.log.Infof("Creating container interface using VPP networking")
	s.log.Infof("Setting tun tag to %s", tunTag)

	// TODO: Clean up old tun if one is found with this tag
	tun := &types.TapV2{
		HostNamespace: netns,
		HostIfName:    contTunName,
		Tag:           tunTag,
		NumRxQueues:   config.TapNumRxQueues,
		RxQueueSize:   config.TapRxQueueSize,
		TxQueueSize:   config.TapTxQueueSize,
		Flags:         types.TapFlagTun,
	}
	if config.TapGSOEnabled {
		tun.Flags |= types.TapFlagGSO | types.TapGROCoalesce
	}
	swIfIndex, err := s.vpp.CreateOrAttachTapV2(tun)
	if err != nil {
		return "", "", s.tunErrorCleanup(contTunName, netns, err, "Error creating tun")
	}
	s.log.Infof("created tun[%d]", swIfIndex)

	err = s.vpp.SetInterfaceRxMode(swIfIndex, types.AllQueues, config.TapRxMode)
	if err != nil {
		return "", "", s.tunErrorCleanup(contTunName, netns, err, "error SetInterfaceRxMode on tun interface")
	}

	// configure vpp side tun
	err = s.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		return "", "", s.tunErrorCleanup(contTunName, netns, err, "error setting vpp tun %d unnumbered", swIfIndex)
	}
	if interfaceConfig.Hasv4 && interfaceConfig.NeedSnat {
		s.log.Infof("Enable tun[%d] SNAT v4", swIfIndex)
		err = s.vpp.EnableCalicoSNAT(swIfIndex, false)
		if err != nil {
			return "", "", s.tunErrorCleanup(contTunName, netns, err, "Error enabling ip4 snat")
		}
	}
	if interfaceConfig.Hasv6 && interfaceConfig.NeedSnat {
		s.log.Infof("Enable tun[%d] SNAT v6", swIfIndex)
		err = s.vpp.EnableCalicoSNAT(swIfIndex, true)
		if err != nil {
			return "", "", s.tunErrorCleanup(contTunName, netns, err, "Error enabling ip6 snat")
		}
	}

	if doHostSideConf {
		err = ns.WithNetNSPath(netns, s.configureNamespaceSideTun(interfaceConfig, swIfIndex, contTunName))
		if err != nil {
			return "", "", s.tunErrorCleanup(contTunName, netns, err, "Error enabling ip6")
		}
	}

	err = s.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return "", "", s.tunErrorCleanup(contTunName, netns, err, "error setting new tun up")
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = s.SetupVppRoutes(swIfIndex, interfaceConfig)
	if err != nil {
		return "", "", s.tunErrorCleanup(contTunName, netns, err, "error adding vpp side routes for interface: %s", tunTag)
	}

	s.log.Infof("Setup tun[%d] complete", swIfIndex)
	// XXX: container MAC doesn't make sense anymore, we just pass back a constant one. How does calico / k8s use it?
	return swIfIdxToIfName(swIfIndex), "02:00:00:00:00:00", err
}

func (s *Server) delVppInterfaceHandleRoutes(swIfIndex uint32, isIPv6 bool) error {
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

	s.log.Infof("found matching VPP tun[%d]", swIfIndex)
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

	// Delete tun
	err = s.vpp.DelTap(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "tun deletion failed")
	}
	s.log.Infof("deleted tun[%d]", swIfIndex)

	return nil
}
