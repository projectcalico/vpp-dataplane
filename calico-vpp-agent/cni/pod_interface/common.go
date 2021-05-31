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
	"bytes"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	gcommon "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
	"net"
)

type PodInterfaceDriverData struct {
	log          *logrus.Entry
	vpp          *vpplink.VppLink
	isL3         bool
	name         string
	NDataThreads int
}

func getPodIPNet(swIfIndex uint32, isv6 bool) *net.IPNet {
	if isv6 {
		return &net.IPNet{
			IP:   net.IP{0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(swIfIndex >> 24), byte(swIfIndex >> 16), byte(swIfIndex >> 8), byte(swIfIndex)},
			Mask: net.CIDRMask(128, 128),
		}
	}
	return &net.IPNet{
		IP:   net.IPv4(byte(169), byte(254), byte(swIfIndex>>8), byte(swIfIndex)),
		Mask: net.CIDRMask(32, 32),
	}
}

func (i *PodInterfaceDriverData) SearchPodInterface(podSpec *storage.LocalPodSpec) (swIfIndex uint32) {
	tag := podSpec.GetInterfaceTag(i.name)
	i.log.Infof("looking for tag %s", tag)
	err, swIfIndex := i.vpp.SearchInterfaceWithTag(tag)
	if err != nil {
		i.log.Warnf("error searching interface with tag %s %s", tag, err)
		return 0
	} else if swIfIndex == vpplink.INVALID_SW_IF_INDEX {
		return 0
	}
	return swIfIndex
}

func (i *PodInterfaceDriverData) AddPodInterfaceToVPP(podSpec *storage.LocalPodSpec) (swIfIndex uint32, err error) {
	return 0, nil
}

func (i *PodInterfaceDriverData) DelPodInterfaceFromVPP(swIfIndex uint32) {
	return
}

func (i *PodInterfaceDriverData) Create(podSpec *storage.LocalPodSpec) (swIfIndex uint32, err error) {
	swIfIndex = i.SearchPodInterface(podSpec)
	if swIfIndex != 0 {
		swIfIndex, err = i.AddPodInterfaceToVPP(podSpec)
		if err != nil {
			return 0, err
		}
	}
	err = i.DoPodInterfaceConfiguration(podSpec, swIfIndex)
	if err != nil {
		return swIfIndex, err
	}
	err = i.DoPodRoutesConfiguration(podSpec, swIfIndex)
	if err != nil {
		return swIfIndex, err
	}
	return swIfIndex, nil
}

func (i *PodInterfaceDriverData) Delete(podSpec *storage.LocalPodSpec) {
	swIfIndex := i.SearchPodInterface(podSpec)
	if swIfIndex == 0 {
		i.log.Debugf("interface not found %s", podSpec.GetInterfaceTag(i.name))
		return
	}
	i.UndoPodRoutesConfiguration(swIfIndex)
	i.UndoPodInterfaceConfiguration(swIfIndex)
	i.DelPodInterfaceFromVPP(swIfIndex)
}

func (i *PodInterfaceDriverData) delPodInterfaceHandleRoutes(swIfIndex uint32, isIPv6 bool) error {
	// Delete connected routes
	// TODO: Make TableID configurable?
	routes, err := i.vpp.GetRoutes(0, isIPv6)
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

		i.log.Infof("Delete VPP route %s", route.String())
		err = i.vpp.RouteDel(&route)
		if err != nil {
			i.log.Errorf("Delete VPP route %s errored: %v", route.String(), err)
		}
	}
	return nil
}

func (i *PodInterfaceDriverData) UndoPodRoutesConfiguration(swIfIndex uint32) {
	err := i.delPodInterfaceHandleRoutes(swIfIndex, true /* isIp6 */)
	if err != nil {
		i.log.Warnf("Error deleting ip6 routes %s", err)
	}
	err = i.delPodInterfaceHandleRoutes(swIfIndex, false /* isIp6 */)
	if err != nil {
		i.log.Warnf("Error deleting ip4 routes %s", err)
	}
}

func (i *PodInterfaceDriverData) UndoPodInterfaceConfiguration(swIfIndex uint32) {
	i.log.Infof("found matching VPP tun[%d]", swIfIndex)
	err := i.vpp.InterfaceAdminDown(swIfIndex)
	if err != nil {
		i.log.Errorf("InterfaceAdminDown errored %s", err)
	}

	err = i.vpp.RemovePodInterface(swIfIndex)
	if err != nil {
		i.log.Errorf("error deregistering pod interface: %v", err)
	}
}

func (i *PodInterfaceDriverData) DoPodRoutesConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) error {
	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	if i.isL3 {
		err := i.vpp.RoutesAdd(podSpec.GetContainerIps(), &types.RoutePath{
			SwIfIndex: swIfIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		}
		return nil
	}
	for _, containerIP := range podSpec.GetContainerIps() {
		addr := getPodIPNet(swIfIndex, types.IsIP6(containerIP.IP))
		route := types.Route{
			Dst: containerIP,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
				Gw:        addr.IP,
			}},
		}
		err := i.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}
	}
	hardwareAddr, err := net.ParseMAC(config.ContainerSideMacAddressString)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse mac: %s", config.ContainerSideMacAddressString)
	}

	hasv4, hasv6 := podSpec.Hasv46()
	if hasv4 {
		err = i.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           getPodIPNet(swIfIndex, false /* isv6 */).IP,
			HardwareAddr: hardwareAddr,
			Flags:        types.IPNeighborStatic,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
	}
	if hasv6 {
		err = i.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           getPodIPNet(swIfIndex, true /* isv6 */).IP,
			HardwareAddr: hardwareAddr,
			Flags:        types.IPNeighborStatic,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
	}
	return nil
}

func (i *PodInterfaceDriverData) DoPodInterfaceConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) (err error) {
	if i.NDataThreads > 0 {
		for queue := 0; queue < config.TapNumRxQueues; queue++ {
			worker := (int(swIfIndex)*config.TapNumRxQueues + queue) % i.NDataThreads
			err = i.vpp.SetInterfaceRxPlacement(swIfIndex, queue, worker, false /*main*/)
			if err != nil {
				i.log.Warnf("failed to set tun[%d] queue%d worker%d (tot workers %d): %v", swIfIndex, queue, worker, i.NDataThreads, err)
			}
		}
	}

	// configure vpp side tun
	err = i.vpp.SetInterfaceVRF(swIfIndex, gcommon.PodVRFIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting vpp tun %d in pod vrf", swIfIndex)
	}

	hasv4, hasv6 := podSpec.Hasv46()
	if i.isL3 {
		err = i.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
		if err != nil {
			return errors.Wrapf(err, "error setting vpp tun %d unnumbered", swIfIndex)
		}
	} else {
		/* L2 */
		err = i.vpp.SetPromiscOn(swIfIndex)
		if err != nil {
			return errors.Wrapf(err, "Error setting memif promisc")
		}
		if hasv4 {
			addr := getPodIPNet(swIfIndex, false /* isv6 */)
			err = i.vpp.AddInterfaceAddress(swIfIndex, addr)
			if err != nil {
				return errors.Wrapf(err, "error setting vpp if[%d] address %s", swIfIndex, addr)
			}
		}
		if hasv6 {
			addr := getPodIPNet(swIfIndex, true /* isv6 */)
			err = i.vpp.AddInterfaceAddress(swIfIndex, addr)
			if err != nil {
				return errors.Wrapf(err, "error setting vpp if[%d] address %s", swIfIndex, addr)
			}
		}
	}

	if hasv4 && podSpec.NeedsSnat {
		i.log.Infof("Enable tun[%d] SNAT v4", swIfIndex)
		err = i.vpp.EnableCnatSNAT(swIfIndex, false)
		if err != nil {
			return errors.Wrapf(err, "Error enabling ip4 snat")
		}
	}
	if hasv6 && podSpec.NeedsSnat {
		i.log.Infof("Enable tun[%d] SNAT v6", swIfIndex)
		err = i.vpp.EnableCnatSNAT(swIfIndex, true)
		if err != nil {
			return errors.Wrapf(err, "Error enabling ip6 snat")
		}
	}

	err = i.vpp.RegisterPodInterface(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error registering pod interface")
	}

	err = i.vpp.CnatEnableFeatures(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error configuring nat on pod interface")
	}

	err = i.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting new tun up")
	}

	err = i.vpp.SetInterfaceRxMode(swIfIndex, types.AllQueues, config.TapRxMode)
	if err != nil {
		return errors.Wrapf(err, "error SetInterfaceRxMode on tun interface")
	}
	return nil
}
