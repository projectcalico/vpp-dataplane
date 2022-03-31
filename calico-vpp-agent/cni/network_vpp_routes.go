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
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (s *Server) RoutePodInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32, isL3 bool) error {
	for _, containerIP := range podSpec.GetContainerIps() {
		var route types.Route
		if podSpec.NetworkName == "" {
			route = types.Route{
				Dst: containerIP,
				Paths: []types.RoutePath{{
					SwIfIndex: swIfIndex,
				}},
			}
			s.log.Infof("pod(add) route [podVRF ->MainIF] %s", route.String())
		} else {
			idx := 0
			if vpplink.IsIP6(containerIP.IP) {
				idx = 1
			}
			route = types.Route{
				Dst: containerIP,
				Paths: []types.RoutePath{{
					SwIfIndex: swIfIndex,
				}},
				Table: s.networkDefinitions[podSpec.NetworkName].VRF.Tables[idx],
			}
			s.log.Infof("pod(add) route [podVRF ->MainIF] %s", route.String())
		}
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "Cannot adding route [podVRF ->MainIF] %s", route.String())
		} else {
			stack.Push(s.vpp.RouteDel, &route)
		}
		if !isL3 {
			s.log.Infof("pod(add) neighbor if[%d] %s", swIfIndex, containerIP.IP.String())
			err = s.vpp.AddNeighbor(&types.Neighbor{
				SwIfIndex:    swIfIndex,
				IP:           containerIP.IP,
				HardwareAddr: common.ContainerSideMacAddress,
			})
			if err != nil {
				return errors.Wrapf(err, "Error adding neighbor if[%d] %s", swIfIndex, containerIP.IP.String())
			}
		}
	}
	return nil
}

func (s *Server) UnroutePodInterface(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	for _, containerIP := range podSpec.GetContainerIps() {
		var route types.Route
		if podSpec.NetworkName == "" {
			route = types.Route{
				Dst: containerIP,
				Paths: []types.RoutePath{{
					SwIfIndex: swIfIndex,
				}},
			}
			s.log.Infof("pod(del) route [podVRF ->MainIF] %s", route.String())
		} else {
			idx := 0
			if vpplink.IsIP6(containerIP.IP) {
				idx = 1
			}
			route = types.Route{
				Dst: containerIP,
				Paths: []types.RoutePath{{
					SwIfIndex: swIfIndex,
				}},
				Table: s.networkDefinitions[podSpec.NetworkName].VRF.Tables[idx],
			}
			s.log.Infof("pod(del) route [podVRF ->MainIF] %s", route.String())
		}
		err := s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Warnf("Error deleting route [podVRF ->MainIF] %s : %s", route.String(), err)
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
			ID: vpplink.InvalidID,
			// TableId:    podSpec.VrfId,
			Addr:       containerIP.IP,
			Path:       path,
			PortRanges: portRanges,
		}

		vrfId := podSpec.GetVrfId(vpplink.IpFamilyV4) // pbl only supports v4 ?
		s.log.Infof("pod(add) PBL client for %s VRF %d", containerIP.IP, vrfId)
		pblIndex, err := s.vpp.AddPblClient(&client)
		if err != nil {
			return errors.Wrapf(err, "error adding PBL client for %s VRF %d", containerIP.IP, vrfId)
		} else {
			stack.Push(s.vpp.DelPblClient, pblIndex)
		}
		podSpec.PblIndexes = append(podSpec.PblIndexes, pblIndex)

		if !isL3 {
			s.log.Infof("pod(add) neighbor if[%d] %s", swIfIndex, containerIP.IP.String())
			err = s.vpp.AddNeighbor(&types.Neighbor{
				SwIfIndex:    swIfIndex,
				IP:           containerIP.IP,
				HardwareAddr: common.ContainerSideMacAddress,
			})
			if err != nil {
				return errors.Wrapf(err, "Cannot adding neighbor if[%d] %s", swIfIndex, containerIP.IP.String())
			}
		}
	}
	return nil
}

func (s *Server) UnroutePblPortsPodInterface(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	for _, pblIndex := range podSpec.PblIndexes {
		s.log.Infof("pod(del) PBL client[%d]", pblIndex)
		err := s.vpp.DelPblClient(pblIndex)
		if err != nil {
			s.log.Warnf("Error deleting pbl conf %s", err)
		}
	}
}

func (s *Server) CreatePodVRF(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	/* Create and Setup the per-pod VRF */
	for _, ipFamily := range vpplink.IpFamilies {
		vrfId, err := s.vpp.AllocateVRF(ipFamily.IsIp6, podSpec.GetVrfTag(ipFamily))
		podSpec.SetVrfId(vrfId, ipFamily)
		s.log.Debugf("Allocated %s VRF ID:%d", ipFamily.Str, vrfId)
		if err != nil {
			return errors.Wrapf(err, "error allocating VRF %s", ipFamily.Str)
		} else {
			stack.Push(s.vpp.DelVRF, vrfId, ipFamily.IsIp6)
		}
	}

	for idx, ipFamily := range vpplink.IpFamilies {
		vrfId := podSpec.GetVrfId(ipFamily)
		if podSpec.NetworkName == "" { // no multi net
			s.log.Infof("pod(add) VRF %d %s default route via VRF %d", vrfId, ipFamily.Str, common.PodVRFIndex)
			err = s.vpp.AddDefaultRouteViaTable(podSpec.GetVrfId(ipFamily), common.PodVRFIndex, ipFamily.IsIp6)
			if err != nil {
				return errors.Wrapf(err, "error adding VRF %d %s default route via VRF %d", vrfId, ipFamily.Str, common.PodVRFIndex)
			} else {
				stack.Push(s.vpp.DelDefaultRouteViaTable, vrfId, common.PodVRFIndex, ipFamily.IsIp6)
			}
		} else {
			netDef, found := s.networkDefinitions[podSpec.NetworkName]
			if !found {
				return errors.Errorf("network %s not found", podSpec.NetworkName)
			}
			networkVRF := netDef.VRF.Tables[idx]
			s.log.Infof("Adding VRF %d %s default route via VRF %d", vrfId, ipFamily.Str, networkVRF)
			err = s.vpp.AddDefaultRouteViaTable(podSpec.GetVrfId(ipFamily), networkVRF, ipFamily.IsIp6)
			if err != nil {
				return errors.Wrapf(err, "error adding VRF %d %s default route via VRF %d", vrfId, ipFamily.Str, networkVRF)
			} else {
				stack.Push(s.vpp.DelDefaultRouteViaTable, vrfId, networkVRF, ipFamily.IsIp6)
			}
		}
	}
	return nil
}

func (s *Server) DeletePodVRF(podSpec *storage.LocalPodSpec) error {
	var err error
	for idx, ipFamily := range vpplink.IpFamilies {
		if podSpec.NetworkName == "" {
			vrfId := podSpec.GetVrfId(ipFamily)
			s.log.Infof("pod(del) VRF %d %s default route via VRF %d", vrfId, ipFamily.Str, common.PodVRFIndex)
			err = s.vpp.DelDefaultRouteViaTable(vrfId, common.PodVRFIndex, ipFamily.IsIp6)
			if err != nil {
				s.log.Errorf("Error  VRF %d %s default route via VRF %d : %s", vrfId, ipFamily.Str, common.PodVRFIndex, err)
			}
		} else {
			netDef, found := s.networkDefinitions[podSpec.NetworkName]
			if !found {
				return errors.Errorf("network %s not found", podSpec.NetworkName)
			}
			networkVRF := netDef.VRF.Tables[idx]
			vrfId := podSpec.GetVrfId(ipFamily)
			s.log.Infof("Deleting VRF %d %s default route via VRF %d", vrfId, ipFamily.Str, networkVRF)
			err = s.vpp.DelDefaultRouteViaTable(vrfId, networkVRF, ipFamily.IsIp6)
			if err != nil {
				s.log.Errorf("Error  VRF %d %s default route via VRF %d : %s", vrfId, ipFamily.Str, networkVRF, err)
			}
		}
	}

	for _, ipFamily := range vpplink.IpFamilies {
		vrfId := podSpec.GetVrfId(ipFamily)
		s.log.Infof("pod(del) VRF %d %s", vrfId, ipFamily.Str)
		err = s.vpp.DelVRF(vrfId, ipFamily.IsIp6)
		if err != nil {
			s.log.Errorf("Error deleting VRF %d %s : %s", vrfId, ipFamily.Str, err)
		}
	}
	return nil
}

func (s *Server) CreateVRFRoutesToPod(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the main table route the container address to its VRF */
		route := types.Route{
			Dst: containerIP,
			Paths: []types.RoutePath{{
				Table:     podSpec.GetVrfId(vpplink.IpFamilyFromIPNet(containerIP)),
				SwIfIndex: types.InvalidID,
			}},
		}
		s.log.Infof("pod(add) route [mainVRF->PodVRF] %s", route.String())
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			return errors.Wrapf(err, "error adding route [mainVRF ->PodVRF] %s", route.String())
		} else {
			stack.Push(s.vpp.RouteDel, &route)
		}
	}
	return nil
}

func (s *Server) DeleteVRFRoutesToPod(podSpec *storage.LocalPodSpec) {
	var err error = nil
	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the main table route the container address to its VRF */
		route := types.Route{
			Dst: containerIP,
			Paths: []types.RoutePath{{
				Table:     podSpec.GetVrfId(vpplink.IpFamilyFromIPNet(containerIP)),
				SwIfIndex: types.InvalidID,
			}},
		}
		s.log.Infof("pod(del) route [mainVRF->PodVRF] %s", route.String())
		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Errorf("error deleting vpp side routes route [mainVRF ->PodVRF] %s : %s", route.String(), err)
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
		s.log.Infof("pod(add) route [puntVRF->PuntIF] %s", route.String())
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
		s.log.Infof("pod(del) route [puntVRF->PuntIF] %s", route.String())
		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Errorf("error deleting route [puntVRF ->PuntIF] %s : %s", route.String(), err)
		}
	}
}
