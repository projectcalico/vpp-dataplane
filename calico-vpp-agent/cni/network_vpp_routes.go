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
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (s *Server) RoutePodInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32, isL3 bool) error {
	for _, containerIP := range podSpec.GetContainerIps() {
		route := types.Route{
			Dst:   containerIP,
			Table: podSpec.VrfId,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		}
		s.log.Infof("Add route [podVRF ->MainIF] %s", route.String())
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		} else {
			stack.Push(s.vpp.RouteDel, &route)
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

func (s *Server) UnroutePodInterface(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	for _, containerIP := range podSpec.GetContainerIps() {
		route := types.Route{
			Dst:   containerIP,
			Table: podSpec.VrfId,
			Paths: []types.RoutePath{{
				SwIfIndex: swIfIndex,
			}},
		}
		s.log.Infof("Del route [podVRF ->MainIF] %s", route.String())
		err := s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Warnf("Error deleting route %s", err)
		}
	}
}

func (s *Server) RoutePblPortsPodInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32, isL3 bool) (err error) {
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
		} else {
			stack.Push(s.vpp.DelPblClient, pblIndex)
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

func (s *Server) UnroutePblPortsPodInterface(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	for _, pblIndex := range podSpec.PblIndexes {
		err := s.vpp.DelPblClient(pblIndex)
		if err != nil {
			s.log.Warnf("Error deleting pbl conf %s", err)
		}
	}
}

func (s *Server) CreateVRFandRoutesToPod(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	/* Create and Setup the per-pod VRF */
	for _, ipFamily := range vpplink.IpFamilies {
		vrfName := getInterfaceVrfName(podSpec, ipFamily.Str)
		err = s.vpp.AddVRF(podSpec.VrfId, ipFamily.IsIp6, vrfName)
		if err != nil {
			return err
		} else {
			stack.Push(s.vpp.DelVRF, podSpec.VrfId, ipFamily.IsIp6, vrfName)
		}
	}

	for _, ipFamily := range vpplink.IpFamilies {
		err = s.vpp.AddDefaultRouteViaTable(podSpec.VrfId, common.PodVRFIndex, ipFamily.IsIp6)
		if err != nil {
			return err
		} else {
			stack.Push(s.vpp.DelDefaultRouteViaTable, podSpec.VrfId, common.PodVRFIndex, ipFamily.IsIp6)
		}
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the main table route the container address to its VRF */
		route := types.Route{
			Dst: containerIP,
			Paths: []types.RoutePath{{
				Table:     podSpec.VrfId,
				SwIfIndex: types.InvalidID,
			}},
		}
		s.log.Infof("Add route [mainVRF ->PodVRF] %s", route.String())
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		} else {
			stack.Push(s.vpp.RouteDel, &route)
		}
	}
	return nil
}

func (s *Server) DeleteVRFandRoutesToPod(podSpec *storage.LocalPodSpec) {
	var err error = nil
	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the main table route the container address to its VRF */
		route := types.Route{
			Dst: containerIP,
			Paths: []types.RoutePath{{
				Table:     podSpec.VrfId,
				SwIfIndex: types.InvalidID,
			}},
		}
		err := s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Errorf("error deleting vpp side routes for interface %s", err)
		}
	}

	for _, ipFamily := range vpplink.IpFamilies {
		err = s.vpp.DelDefaultRouteViaTable(podSpec.VrfId, common.PodVRFIndex, ipFamily.IsIp6)
		if err != nil {
			s.log.Errorf("Error deleting default route to VRF %s", err)
		}
	}

	for _, ipFamily := range vpplink.IpFamilies {
		vrfName := getInterfaceVrfName(podSpec, ipFamily.Str)
		err = s.vpp.DelVRF(podSpec.VrfId, ipFamily.IsIp6, vrfName)
		if err != nil {
			s.log.Errorf("Error deleting VRF %s", err)
		}
	}
}

func (s *Server) SetupPuntRoutes(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) (err error) {
	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the punt table (where all punted traffics ends),
		 * route the container to the tun */
		route := types.Route{
			Table: common.PuntTableId,
			Dst:   containerIP,
			Paths: []types.RoutePath{{SwIfIndex: swIfIndex}},
		}
		s.log.Infof("Add route [puntVRF ->PuntIF] %s", route.String())
		err = s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "error adding vpp side routes for interface")
		} else {
			stack.Push(s.vpp.RouteDel, &route)
		}
	}
	return nil
}

func (s *Server) RemovePuntRoutes(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	var err error = nil
	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the punt table (where all punted traffics ends), route the container to the tun */
		route := types.Route{
			Table: common.PuntTableId,
			Dst:   containerIP,
			Paths: []types.RoutePath{{SwIfIndex: swIfIndex}},
		}
		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Errorf("error deleting vpp side routes for interface %s", err)
		}
	}
}
