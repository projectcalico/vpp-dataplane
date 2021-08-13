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

package cni

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (s *Server) delPodInterfaceHandleRoutes(swIfIndex uint32, isIPv6 bool) error {
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

		s.log.Infof("Delete VPP route %s", route.String())
		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Errorf("Delete VPP route %s errored: %v", route.String(), err)
		}
	}
	return nil
}

func (s *Server) UndoPodRoutesConfiguration(swIfIndex uint32) {
	err := s.delPodInterfaceHandleRoutes(swIfIndex, true /* isIp6 */)
	if err != nil {
		s.log.Warnf("Error deleting ip6 routes %s", err)
	}
	err = s.delPodInterfaceHandleRoutes(swIfIndex, false /* isIp6 */)
	if err != nil {
		s.log.Warnf("Error deleting ip4 routes %s", err)
	}
}

func (s *Server) DoPodPblConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32, isL3 bool) (err error) {
	for _, containerIP := range podSpec.GetContainerIps() {
		path := types.RoutePath{
			SwIfIndex: swIfIndex,
		}
		if !isL3 {
			path.Gw = containerIP.IP
		}

		portRanges := make([]types.PblPortRange, 0)
		for _, pc := range podSpec.IfPortConfigs {
			portRanges = append(portRanges, types.PblPortRange{
				Start: pc.Start,
				End:   pc.End,
				Proto: pc.Proto,
			})
		}

		client := types.PblClient{
			ID:         vpplink.InvalidID,
			TableId:    podSpec.VrfId,
			Addr:       containerIP.IP,
			Path:       path,
			PortRanges: portRanges,
		}
		pblIndex, err := s.vpp.AddPblClient(&client)
		if err != nil {
			return errors.Wrapf(err, "error adding PBL client")
		}
		podSpec.PblIndexes = append(podSpec.PblIndexes, pblIndex)

		if !isL3 {
			err = s.vpp.AddNeighbor(&types.Neighbor{
				SwIfIndex:    swIfIndex,
				IP:           containerIP.IP,
				HardwareAddr: config.ContainerSideMacAddress,
			})
			if err != nil {
				return errors.Wrapf(err, "Cannot add neighbor in VPP")
			}
		}
	}
	return nil
}

func (s *Server) DoPodRoutesConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32, isL3 bool) error {
	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	// if isL3 {
	// 	s.log.Infof("Adding route %s if%d", podSpec.GetContainerIps(), swIfIndex)
	// 	err := s.vpp.RoutesAdd(podSpec.GetContainerIps(), &types.RoutePath{
	// 		SwIfIndex: swIfIndex,
	// 	})
	// 	if err != nil {
	// 		return errors.Wrapf(err, "error adding vpp side routes for interface")
	// 	}
	// 	return nil
	// }

	for _, containerIP := range podSpec.GetContainerIps() {
		s.log.Infof("Adding route %s if%d", containerIP, swIfIndex)
		route := types.Route{
			Dst:   containerIP,
			Table: podSpec.VrfId,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		}
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}
		if !isL3 {
			err = s.vpp.AddNeighbor(&types.Neighbor{
				SwIfIndex:    swIfIndex,
				IP:           containerIP.IP,
				HardwareAddr: config.ContainerSideMacAddress,
			})
			if err != nil {
				return errors.Wrapf(err, "Cannot add neighbor in VPP")
			}
		}
	}
	return nil
}

func (s *Server) UndoPodPblConfiguration(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	for _, pblIndex := range podSpec.PblIndexes {
		err := s.vpp.DelPblClient(pblIndex)
		if err != nil {
			s.log.Warnf("Error deleting pbl conf %s", err)
		}
	}
}
