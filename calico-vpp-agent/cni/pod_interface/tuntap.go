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
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type TunTapPodInterfaceDriver struct {
	PodInterfaceDriverData
	felixConfig         *felixConfig.Config
	ipipEncapRefCounts  int /* how many ippools with IPIP */
	vxlanEncapRefCounts int /* how many ippools with VXLAN */
}

func NewTunTapPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *TunTapPodInterfaceDriver {
	i := &TunTapPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.name = "tun"
	return i
}

func reduceMtuIf(podMtu *int, tunnelMtu int, tunnelEnabled bool) {
	if tunnelEnabled && tunnelMtu != 0 && tunnelMtu < *podMtu {
		*podMtu = tunnelMtu
	}
}

/**
 * Computes the pod MTU from a requested mtu : podSpecMtu (typically specified in the podSpec)
 * the felixConfig (having some encap details)
 * and other sources (typically ippool) for vxlanEnabled / ipInIpEnabled
 */
func (i *TunTapPodInterfaceDriver) computePodMtu(podSpecMtu int, fc *felixConfig.Config, ipipEnabled bool, vxlanEnabled bool) (podMtu int) {
	if podSpecMtu > 0 {
		podMtu = podSpecMtu
	} else {
		ipipEnabled := ipipEnabled || (fc.IpInIpEnabled != nil && *fc.IpInIpEnabled)
		vxlanEnabled := vxlanEnabled || (fc.VXLANEnabled != nil && *fc.VXLANEnabled)

		// Reproduce felix algorithm in determinePodMTU to determine pod MTU
		// The part where it defaults to the host MTU is done in AddVppInterface
		// TODO: move the code that retrieves the host mtu to this module...
		podMtu = config.HostMtu
		reduceMtuIf(&podMtu, vpplink.DefaultIntTo(fc.IpInIpMtu, config.HostMtu-20), ipipEnabled)
		reduceMtuIf(&podMtu, vpplink.DefaultIntTo(fc.VXLANMTU, config.HostMtu-50), vxlanEnabled)
		reduceMtuIf(&podMtu, vpplink.DefaultIntTo(fc.WireguardMTU, config.HostMtu-60), fc.WireguardEnabled)
		reduceMtuIf(&podMtu, config.HostMtu-60, config.EnableIPSec)
	}

	if podMtu > config.HostMtu {
		i.log.Warnf("Configured MTU (%d) is larger than detected host interface MTU (%d)", podMtu, config.HostMtu)
	}

	return podMtu
}

func (i *TunTapPodInterfaceDriver) SetFelixConfig(felixConfig *felixConfig.Config) {
	i.felixConfig = felixConfig
}

/**
 * This is called when the felix config or ippool encap refcount change,
 * and update the linux mtu accordingly.
 *
 */
func (i *TunTapPodInterfaceDriver) FelixConfigChanged(newFelixConfig *felixConfig.Config, ipipEncapRefCountDelta int, vxlanEncapRefCountDelta int, podSpecs map[string]storage.LocalPodSpec) {
	if newFelixConfig == nil {
		newFelixConfig = i.felixConfig
	}
	if i.felixConfig != nil {
		for name, podSpec := range podSpecs {
			oldMtu := i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts > 0, i.vxlanEncapRefCounts > 0)
			newMtu := i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts+ipipEncapRefCountDelta > 0, i.vxlanEncapRefCounts+vxlanEncapRefCountDelta > 0)
			if oldMtu != newMtu {
				i.log.Infof("pod(upd) reconfiguring mtu=%d pod=%s", newMtu, name)
				err := ns.WithNetNSPath(podSpec.NetnsName, func(ns.NetNS) error {
					containerInterface, err := netlink.LinkByName(podSpec.InterfaceName)
					if err != nil {
						return errors.Wrapf(err, "failed to lookup if=%s pod=%s", podSpec.InterfaceName, name)
					}
					err = netlink.LinkSetMTU(containerInterface, newMtu)
					if err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					i.log.Errorf("failed to set mtu pod=%s: %v", name, err)
				}
			}
		}
	}

	i.felixConfig = newFelixConfig
	i.ipipEncapRefCounts = i.ipipEncapRefCounts + ipipEncapRefCountDelta
	i.vxlanEncapRefCounts = i.vxlanEncapRefCounts + vxlanEncapRefCountDelta
}

func (i *TunTapPodInterfaceDriver) CreateInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) error {
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
		HostMtu:       i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts > 0, i.vxlanEncapRefCounts > 0),
	}

	if podSpec.TunTapIsL3 {
		tun.Flags |= types.TapFlagTun
	}

	if config.PodGSOEnabled {
		tun.Flags |= types.TapFlagGSO | types.TapGROCoalesce
	}

	i.log.Debugf("Add request pod MTU: %d, computed %d", podSpec.Mtu, tun.HostMtu)

	swIfIndex, err := i.vpp.CreateOrAttachTapV2(tun)
	if err != nil {
		return errors.Wrapf(err, "Error creating tun")
	} else {
		stack.Push(i.vpp.DelTap, swIfIndex)
	}
	err = i.SpreadTxQueuesOnWorkers(swIfIndex, tun.NumTxQueues)
	if err != nil {
		return err
	}

	podSpec.TunTapSwIfIndex = swIfIndex
	i.log.Infof("pod(add) tun swIfIndex=%d", swIfIndex)

	err = i.DoPodIfNatConfiguration(podSpec, stack, swIfIndex)
	if err != nil {
		return err
	}

	err = i.DoPodInterfaceConfiguration(podSpec, stack, swIfIndex, podSpec.TunTapIsL3)
	if err != nil {
		return err
	}

	if doHostSideConf {
		err = i.configureLinux(podSpec, swIfIndex)
		if err != nil {
			return err
		}
	}
	i.log.Infof("pod(add) Done tun swIfIndex=%d", swIfIndex)

	return nil
}

func (i *TunTapPodInterfaceDriver) DeleteInterface(podSpec *storage.LocalPodSpec) {
	i.unconfigureLinux(podSpec)

	i.UndoPodInterfaceConfiguration(podSpec.TunTapSwIfIndex)
	i.UndoPodIfNatConfiguration(podSpec.TunTapSwIfIndex)

	err := i.vpp.DelTap(podSpec.TunTapSwIfIndex)
	if err != nil {
		i.log.Warnf("Error deleting tun[%d] %s", podSpec.TunTapSwIfIndex, err)
	}
	i.log.Infof("pod(del) tun swIfIndex=%d", podSpec.TunTapSwIfIndex)

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
			i.log.Infof("pod(del) Found linux address=%s scope=%d", addr.IP.String(), addr.Scope)
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
		i.log.Info("pod(add) Configuring IPv4 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", ipFwd); err != nil {
			return err
		}
	}
	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasv6 {
		i.log.Info("pod(add) Configuring IPv6 forwarding")
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
			i.log.Infof("pod(add) tun in NS has v6 swIfIndex=%d", swIfIndex)
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
				i.log.Infof("pod(add) Skipping tun swIfIndex=%d route=%s", swIfIndex, route.String())
				continue
			}
			i.log.Infof("pod(add) tun route swIfIndex=%d linux-ifIndex=%d route=%s", swIfIndex, contTun.Attrs().Index, route.String())
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
			i.log.Infof("pod(add) tun address swIfIndex=%d linux-ifIndex=%d address=%s", swIfIndex, contTun.Attrs().Index, containerIP.String())
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
