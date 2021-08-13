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
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func getInterfaceVrfName(podSpec *storage.LocalPodSpec) string {
	return fmt.Sprintf("pod-%s-table", podSpec.Key())
}

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *storage.LocalPodSpec, doHostSideConf bool) (tunTapSwIfIndex uint32, err error) {
	var loopbackSwIfIndex uint32
	podSpec.NeedsSnat = false
	for _, containerIP := range podSpec.GetContainerIps() {
		podSpec.NeedsSnat = podSpec.NeedsSnat || s.IPNetNeedsSNAT(containerIP)
	}

	stack := s.vpp.NewCleanupStack()

	podSpec.VrfId = vpplink.AllocateID(podVrfAllocator, common.PerPodVRFIndexStart)
	stack.Push(vpplink.FreeID, podVrfAllocator, podSpec.VrfId)
	s.log.Infof("Allocated VrfId:%d for %s", podSpec.VrfId, podSpec.Key())

	err = s.vpp.AddVRF46(podSpec.VrfId, getInterfaceVrfName(podSpec))
	if err != nil {
		goto err
	}
	stack.Push(s.vpp.DelVRF46, podSpec.VrfId, getInterfaceVrfName(podSpec))

	err = s.vpp.AddDefault46RouteViaTable(podSpec.VrfId, common.PodVRFIndex)
	if err != nil {
		goto err
	}
	stack.Push(s.vpp.DelDefault46RouteViaTable, podSpec.VrfId, common.PodVRFIndex)

	loopbackSwIfIndex, err = s.vpp.CreateLoopback(&config.ContainerSideMacAddress)
	if err != nil {
		goto err
	}
	stack.Push(s.vpp.DeleteLoopback, loopbackSwIfIndex)
	podSpec.LoopbackSwIfIndex = loopbackSwIfIndex

	err = s.vpp.SetInterfaceVRF46(loopbackSwIfIndex, podSpec.VrfId)
	if err != nil {
		s.log.Errorf("error setting loopback %d in per pod vrf %s", loopbackSwIfIndex, err)
		goto err
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		err = s.vpp.AddInterfaceAddress(loopbackSwIfIndex, containerIP)
		if err != nil {
			s.log.Errorf("Error adding address to pod loopback interface: %v", err)
			goto err
		}

		/* In the main table route the container address to its VRF */
		route := types.Route{
			Dst: containerIP,
			Paths: []types.RoutePath{{
				Table:     podSpec.VrfId,
				SwIfIndex: types.InvalidID,
			}},
		}
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			s.log.Errorf("error adding vpp side routes for interface %s", err)
			goto err
		}
		stack.Push(s.vpp.RouteDel, &route)
	}

	s.log.Infof("Creating container interface using VPP networking")
	tunTapSwIfIndex, err = s.tuntapDriver.Create(podSpec, doHostSideConf)
	if err != nil {
		goto err
	}
	stack.Push(s.tuntapDriver.Delete, podSpec)
	podSpec.TunTapSwIfIndex = tunTapSwIfIndex

	err = s.vpp.InterfaceSetUnnumbered(tunTapSwIfIndex, loopbackSwIfIndex)
	if err != nil {
		s.log.Errorf("error setting vpp tap unnumbered %s", err)
		goto err
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the punt table (where all punted traffics ends), route the container to the tun */
		route := types.Route{
			Table: common.PuntTableId,
			Dst:   containerIP,
			Paths: []types.RoutePath{{SwIfIndex: tunTapSwIfIndex}},
		}
		err := s.vpp.RouteAdd(&route)
		if err != nil {
			s.log.Errorf("error adding vpp side routes for interface %s", err)
			goto err
		}
		stack.Push(s.vpp.RouteDel, &route)
	}

	if podSpec.EnableMemif {
		s.log.Infof("Creating container memif interface")
		memifSwIfIndex, err := s.memifDriver.Create(podSpec)
		if err != nil {
			goto err
		}
		podSpec.MemifSwIfIndex = memifSwIfIndex

		err = s.vpp.InterfaceSetUnnumbered(memifSwIfIndex, loopbackSwIfIndex)
		if err != nil {
			s.log.Errorf("error setting vpp memif unnumbered %s", err)
			goto err
		}
		stack.Push(s.memifDriver.Delete, podSpec)
	}

	if podSpec.EnableVCL {
		s.log.Infof("Enabling container VCL")
		err = s.vclDriver.Create(podSpec, loopbackSwIfIndex)
		if err != nil {
			goto err
		}
		stack.Push(s.vclDriver.Delete, podSpec)
	}

	/* Routes */
	if !podSpec.EnableVCL {
		err = s.DoPodRoutesConfiguration(podSpec, tunTapSwIfIndex, true /*isL3*/)
		if err != nil {
			goto err
		}

		if podSpec.PortFilteredIfType == storage.VppIfTypeMemif {
			err = s.DoPodPblConfiguration(podSpec, podSpec.MemifSwIfIndex, false /*isL3*/)
			if err != nil {
				goto err
			}
		}
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		s.routingServer.AnnounceLocalAddress(containerIP, false /* isWithdrawal */)
	}

	s.policyServer.WorkloadAdded(&policy.WorkloadEndpointID{
		OrchestratorID: podSpec.OrchestratorID,
		WorkloadID:     podSpec.WorkloadID,
		EndpointID:     podSpec.EndpointID,
	}, tunTapSwIfIndex)

	return tunTapSwIfIndex, err

err:
	stack.Execute()
	return tunTapSwIfIndex, errors.Wrapf(err, "Error creating interface")

}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(podSpec *storage.LocalPodSpec) {
	var err error
	for _, containerIP := range podSpec.GetContainerIps() {
		/* In the punt table (where all punted traffics ends), route the container to the tun */
		route := types.Route{
			Table: common.PuntTableId,
			Dst:   containerIP,
			Paths: []types.RoutePath{{SwIfIndex: podSpec.TunTapSwIfIndex}},
		}
		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Errorf("error deleting vpp side routes for interface %s", err)
		}

		/* In the main table route the container address to its VRF */
		route = types.Route{
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

	/* Routes */
	if !podSpec.EnableVCL {
		s.UndoPodRoutesConfiguration(podSpec.TunTapSwIfIndex)
		if podSpec.PortFilteredIfType == storage.VppIfTypeMemif {
			s.UndoPodPblConfiguration(podSpec, podSpec.MemifSwIfIndex)
		}
	}

	err = s.vpp.DeleteLoopback(podSpec.LoopbackSwIfIndex)
	if err != nil {
		s.log.Errorf("error deleting vpp loopback %s", err)
	}

	containerIPs := s.tuntapDriver.Delete(podSpec)
	for _, containerIP := range containerIPs {
		s.routingServer.AnnounceLocalAddress(&containerIP, true /* isWithdrawal */)
	}

	s.memifDriver.Delete(podSpec)
	s.vclDriver.Delete(podSpec)

	s.vpp.DelDefault46RouteViaTable(podSpec.VrfId, common.PodVRFIndex)

	err = s.vpp.DelVRF46(podSpec.VrfId, getInterfaceVrfName(podSpec))
	if err != nil {
		s.log.Errorf("Error deleting VRF %s", err)
	}
	vpplink.FreeID(podVrfAllocator, podSpec.VrfId)
}
