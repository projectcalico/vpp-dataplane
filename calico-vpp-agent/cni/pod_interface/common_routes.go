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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

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

func (i *PodInterfaceDriverData) DoPodPblConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) (err error) {
	for _, containerIP := range podSpec.GetContainerIps() {
		err = i.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           containerIP.IP,
			HardwareAddr: config.ContainerSideMacAddress,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}

		path := types.RoutePath{
			Gw: containerIP.IP,
		}
		if !i.isL3 {
			path.SwIfIndex = swIfIndex
		}
		portRanges := make([]types.PortRange, 0)
		for _, pc := range podSpec.IfPortConfigs {
			portRanges = append(portRanges, types.PortRange{
				First: pc.Port,
				Last: pc.Port,
			})
		}
		client := types.PblClient{
			ID: ^uint32(0),
			Addr: containerIP.IP,
			Path: path,
			PortRanges: portRanges,
		}
		_, err = i.vpp.AddPblClient(&client)
		if err != nil {
			return errors.Wrapf(err, "error adding PBL client")
		}
	}
	return nil
}

func (i *PodInterfaceDriverData) DoPodAbfConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) (err error) {
	rules := make([]types.ACLRule, 0)
	paths := make([]types.RoutePath, 0)
	for _, containerIP := range podSpec.GetContainerIps() {
		err = i.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           containerIP.IP,
			HardwareAddr: config.ContainerSideMacAddress,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
		paths = append(paths, types.RoutePath{
			SwIfIndex: swIfIndex,
			Gw:        containerIP.IP,
		})
		for _, pc := range podSpec.IfPortConfigs {
			if pc.IfType == i.IfType {
				rules = append(rules, types.ACLRule{
					Dst:     *containerIP,
					Proto:   pc.Proto,
					DstPort: pc.Port,
				})
			}
		}
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
	err = i.vpp.AttachAbfPolicy(abfPolicy.PolicyID, config.DataInterfaceSwIfIndex, false /*isv6*/)
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

func (i *PodInterfaceDriverData) UndoPodPblConfiguration(swIfIndex uint32) {
	/*FIXME*/
	// i.vpp.DelACL
}

func (i *PodInterfaceDriverData) UndoPodAbfConfiguration(swIfIndex uint32) {
	/*FIXME*/
	// i.vpp.DelACL
}
