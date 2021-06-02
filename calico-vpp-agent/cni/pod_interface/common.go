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
)

type PodInterfaceDriverData struct {
	log          *logrus.Entry
	vpp          *vpplink.VppLink
	isL3         bool
	name         string
	NDataThreads int
}

func (i *PodInterfaceDriverData) SearchPodInterface(podSpec *storage.LocalPodSpec) (swIfIndex uint32) {
	tag := podSpec.GetInterfaceTag(i.name)
	i.log.Infof("looking for tag %s", tag)
	err, swIfIndex := i.vpp.SearchInterfaceWithTag(tag)
	if err != nil {
		i.log.Warnf("error searching interface with tag %s %s", tag, err)
		return vpplink.INVALID_SW_IF_INDEX
	} else if swIfIndex == vpplink.INVALID_SW_IF_INDEX {
		return vpplink.INVALID_SW_IF_INDEX
	}
	return swIfIndex
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

func (i *PodInterfaceDriverData) UndoPodAbfConfiguration(swIfIndex uint32) {
	/*FIXME*/
	// i.vpp.DelACL

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

func (i *PodInterfaceDriverData) DoPodAbfConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) (err error) {
	rules := make([]types.ACLRule, 0)
	paths := make([]types.RoutePath, 0)
	for _, containerIP := range podSpec.GetContainerIps() {
		err = i.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           containerIP.IP, //getPodIPNet(swIfIndex, false /* isv6 */).IP,
			HardwareAddr: config.ContainerSideMacAddress,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
		paths = append(paths, types.RoutePath{
			SwIfIndex: swIfIndex,
			Gw:        containerIP.IP,
		})
		rules = append(rules, types.ACLRule{
			Dst:     *containerIP,
			Proto:   types.TCP, // FIXME
			DstPort: 1234,      // FIXME
		})
	}

	acl := types.ACL{Rules: rules}
	err = i.vpp.AddACL(&acl)
	if err != nil {
		return errors.Wrapf(err, "error adding ACL")
	}

	abfPolicy := types.AbfPolicy{
		AclIndex: acl.ACLIndex,
		Paths:    paths,
	}
	err = i.vpp.AddAbfPolicy(&abfPolicy)
	if err != nil {
		return errors.Wrapf(err, "error adding ABF rule")
	}

	/* FIXME */
	err = i.vpp.AttachAbfPolicy(abfPolicy.PolicyID, uint32(1), false /*isv6*/)
	if err != nil {
		return errors.Wrapf(err, "error attaching ABF rule")
	}
	return nil
}

func (i *PodInterfaceDriverData) DoPodRoutesConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) error {
	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	if i.isL3 {
		i.log.Infof("Adding route %s if%d", podSpec.GetContainerIps(), swIfIndex)
		err := i.vpp.RoutesAdd(podSpec.GetContainerIps(), &types.RoutePath{
			SwIfIndex: swIfIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		}
		return nil
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		i.log.Infof("Adding L2 route %s if%d", containerIP, swIfIndex)
		route := types.Route{
			Table: gcommon.PodVRFIndex,
			Dst:   containerIP,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		}
		err := i.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}
		err = i.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           containerIP.IP,
			HardwareAddr: config.ContainerSideMacAddress,
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

	err = i.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting vpp if[%d] unnumbered", swIfIndex)
	}

	if !i.isL3 {
		/* L2 */
		err = i.vpp.SetPromiscOn(swIfIndex)
		if err != nil {
			return errors.Wrapf(err, "Error setting memif promisc")
		}
	}

	hasv4, hasv6 := podSpec.Hasv46()
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
