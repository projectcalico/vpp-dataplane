// Copyright (C) 2021 Cisco Systems Inc.
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

package pod_interface

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TunTapPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func NewTunTapPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *TunTapPodInterfaceDriver {
	i := &TunTapPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.isL3 = true
	i.name = storage.VppTunName
	i.IfType = storage.VppTun
	return i
}

func (i *TunTapPodInterfaceDriver) Create(podSpec *storage.LocalPodSpec, doHostSideConf bool) (swIfIndex uint32, err error) {
	swIfIndex = i.SearchPodInterface(podSpec)
	if swIfIndex == vpplink.INVALID_SW_IF_INDEX {
		swIfIndex, err = i.AddPodInterfaceToVPP(podSpec)
		if err != nil {
			return vpplink.INVALID_SW_IF_INDEX, err
		}
	}
	err = i.DoPodInterfaceConfiguration(podSpec, swIfIndex, 1)
	if err != nil {
		return swIfIndex, err
	}

	if i.IfType == podSpec.DefaultIfType {
		err = i.DoPodRoutesConfiguration(podSpec, swIfIndex)
	} else if podSpec.DefaultIfType != storage.VppVcl {
		err = i.DoPodPblConfiguration(podSpec, swIfIndex)
	}
	if err != nil {
		return swIfIndex, err
	}
	if doHostSideConf {
		err = i.configureLinux(podSpec, swIfIndex)
		if err != nil {
			return swIfIndex, err
		}
	}
	i.log.Infof("Created tun[%d]", swIfIndex)
	return swIfIndex, nil
}

func (i *TunTapPodInterfaceDriver) Delete(podSpec *storage.LocalPodSpec) (containerIPs []net.IPNet) {
	i.log.Infof("Del request %s", podSpec.GetInterfaceTag(i.name))
	swIfIndex := i.SearchPodInterface(podSpec)
	if swIfIndex == vpplink.INVALID_SW_IF_INDEX {
		i.log.Warnf("interface not found %s", podSpec.GetInterfaceTag(i.name))
		return
	}
	containerIPs = i.unconfigureLinux(podSpec)
	if i.IfType == podSpec.DefaultIfType {
		i.UndoPodRoutesConfiguration(swIfIndex)
	} else {
		i.UndoPodPblConfiguration(podSpec, swIfIndex)
	}

	i.UndoPodInterfaceConfiguration(swIfIndex)
	i.DelPodInterfaceFromVPP(swIfIndex)
	return containerIPs

}

func (i *TunTapPodInterfaceDriver) configureLinux(podSpec *storage.LocalPodSpec, swIfIndex uint32) error {
	/* linux side configuration */
	err := ns.WithNetNSPath(podSpec.NetnsName, i.configureNamespaceSideTun(swIfIndex, podSpec))
	if err != nil {
		return errors.Wrapf(err, "Error in linux NS config")
	}
	return nil
}

func (i *TunTapPodInterfaceDriver) unconfigureLinux(podSpec *storage.LocalPodSpec) []net.IPNet {
	containerIPs := make([]net.IPNet, 0)
	devErr := ns.WithNetNSPath(podSpec.NetnsName, func(_ ns.NetNS) error {
		dev, err := netlink.LinkByName(podSpec.InterfaceName)
		if err != nil {
			return err
		}
		addresses, err := netlink.AddrList(dev, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, addr := range addresses {
			i.log.Infof("Found address %s on interface, scope %d", addr.IP.String(), addr.Scope)
			if addr.Scope == unix.RT_SCOPE_LINK {
				continue
			}
			containerIPs = append(containerIPs, net.IPNet{IP: addr.IP, Mask: addr.Mask})
		}
		return nil
	})
	if devErr != nil {
		switch devErr.(type) {
		case netlink.LinkNotFoundError:
			i.log.Warnf("Device to delete not found")
		default:
			i.log.Warnf("error withdrawing interface addresses: %v", devErr)
		}
	}
	return containerIPs
}

func (i *TunTapPodInterfaceDriver) DelPodInterfaceFromVPP(swIfIndex uint32) {
	err := i.vpp.DelTap(swIfIndex)
	if err != nil {
		i.log.Warnf("Error deleting tun[%d] %s", swIfIndex, err)
	}
	i.log.Infof("deleted tun[%d]", swIfIndex)
}

func (i *TunTapPodInterfaceDriver) AddPodInterfaceToVPP(podSpec *storage.LocalPodSpec) (uint32, error) {
	tun := &types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			NumRxQueues:       config.TapNumRxQueues,
			NumTxQueues:       config.TapNumTxQueues,
			RxQueueSize:       config.TapRxQueueSize,
			TxQueueSize:       config.TapTxQueueSize,
			HostInterfaceName: podSpec.InterfaceName,
		},
		HostNamespace: podSpec.NetnsName,
		Tag:           podSpec.GetInterfaceTag(i.name),
		Flags:         types.TapFlagTun,
		HostMtu:       podSpec.GetPodMtu(),
	}
	i.log.Debugf("Add request pod MTU: %d, computed %d", podSpec.Mtu, tun.HostMtu)

	if config.TapGSOEnabled {
		tun.Flags |= types.TapFlagGSO | types.TapGROCoalesce
	}
	swIfIndex, err := i.vpp.CreateOrAttachTapV2(tun)
	if err != nil {
		return 0, fmt.Errorf("Error creating tun")
	}
	i.log.Infof("created tun[%d]", swIfIndex)
	return swIfIndex, nil
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
func (i *TunTapPodInterfaceDriver) configureContainerSysctls(podSpec *storage.LocalPodSpec) error {
	hasv4, hasv6 := podSpec.Hasv46()
	ipFwd := "0"
	if podSpec.AllowIpForwarding {
		ipFwd = "1"
	}
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasv4 {
		i.log.Info("Configuring IPv4 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", ipFwd); err != nil {
			return err
		}
	}
	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasv6 {
		i.log.Info("Configuring IPv6 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", ipFwd); err != nil {
			return err
		}
	}
	return nil
}

func (i *TunTapPodInterfaceDriver) configureNamespaceSideTun(swIfIndex uint32, podSpec *storage.LocalPodSpec) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTun, err := netlink.LinkByName(podSpec.InterfaceName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", podSpec.InterfaceName, err)
		}
		hasv4, hasv6 := podSpec.Hasv46()

		// Do the per-IP version set-up.  Add gateway routes etc.
		if hasv6 {
			i.log.Infof("tun %d in NS has v6", swIfIndex)
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

		for _, route := range podSpec.GetRoutes() {
			isV6 := route.IP.To4() == nil
			if (isV6 && !hasv6) || (!isV6 && !hasv4) {
				i.log.Infof("Skipping tun[%d] route for %s", swIfIndex, route.String())
				continue
			}
			i.log.Infof("Add tun[%d] linux%d route for %s", swIfIndex, contTun.Attrs().Index, route.String())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTun.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       route,
			})
			if err != nil {
				// TODO : in ipv6 '::' already exists
				i.log.Errorf("Error adding tun[%d] route for %s", swIfIndex, route.String())
			}
		}

		// Now add the IPs to the container side of the tun.
		for _, containerIP := range podSpec.GetContainerIps() {
			i.log.Infof("Add tun[%d] linux%d ip %s", swIfIndex, contTun.Attrs().Index, containerIP.String())
			err = netlink.AddrAdd(contTun, &netlink.Addr{IPNet: containerIP})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %s: %v", contTun.Attrs().Name, err)
			}
		}

		if err = i.configureContainerSysctls(podSpec); err != nil {
			return errors.Wrapf(err, "error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	}
}
