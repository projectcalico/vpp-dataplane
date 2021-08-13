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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func getInterfaceVrfName(podSpec *storage.LocalPodSpec) string {
	return fmt.Sprintf("pod-%s-table", podSpec.Key())
}

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *storage.LocalPodSpec, doHostSideConf bool) (tunTapSwIfIndex uint32, err error) {
	podSpec.NeedsSnat = false
	for _, containerIP := range podSpec.GetContainerIps() {
		podSpec.NeedsSnat = podSpec.NeedsSnat || s.IPNetNeedsSNAT(containerIP)
	}

	stack := s.vpp.NewCleanupStack()

    /* Create and Setup the per-pod VRF */
	podSpec.VrfId = vpplink.AllocateID(podVrfAllocator, common.PerPodVRFIndexStart)
	stack.Push(vpplink.FreeID, podVrfAllocator, podSpec.VrfId)
	s.log.Infof("Allocated VrfId:%d for %s", podSpec.VrfId, podSpec.Key())

	err = s.vpp.AddVRF46(podSpec.VrfId, getInterfaceVrfName(podSpec))
	if err != nil {
		goto err
	} else {
		stack.Push(s.vpp.DelVRF46, podSpec.VrfId, getInterfaceVrfName(podSpec))
	}

	err = s.vpp.AddDefault46RouteViaTable(podSpec.VrfId, common.PodVRFIndex)
	if err != nil {
		goto err
	} else {
		stack.Push(s.vpp.DelDefault46RouteViaTable, podSpec.VrfId, common.PodVRFIndex)
	}

    err = s.loopbackDriver.CreateInterface(podSpec)
	if err != nil {
		goto err
	} else {
		stack.Push(s.loopbackDriver.DeleteInterface, podSpec)
	}

	s.log.Infof("Creating container interface using VPP networking")
	err = s.tuntapDriver.CreateInterface(podSpec, doHostSideConf)
	if err != nil {
		goto err
	} else {
		stack.Push(s.tuntapDriver.DeleteInterface, podSpec)
	}

	if podSpec.EnableMemif {
		s.log.Infof("Creating container memif interface")
		err := s.memifDriver.CreateInterface(podSpec)
		if err != nil {
			goto err
		}
	}

	if podSpec.EnableVCL {
		s.log.Infof("Enabling container VCL")
		err = s.vclDriver.CreateInterface(podSpec)
		if err != nil {
			goto err
		} else {
			stack.Push(s.vclDriver.DeleteInterface, podSpec)
		}
	}

	err = s.RoutePodVRF(podSpec)
	if err != nil {
		goto err
	} else {
		stack.Push(s.UnroutePodVRF, podSpec)
	}

	/* Routes */
	if !podSpec.EnableVCL {
		swIfIndex, isL3 := podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		err = s.RoutePodInterface(podSpec, swIfIndex, isL3)
		if err != nil {
			goto err
		}

		swIfIndex, isL3 = podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if swIfIndex != types.InvalidID {
			err = s.RoutePblPortsPodInterface(podSpec, podSpec.MemifSwIfIndex, isL3)
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
	var err error = nil

	/* Routes */
	if !podSpec.EnableVCL {
		swIfIndex, _ := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if swIfIndex != types.InvalidID {
			s.UnroutePblPortsPodInterface(podSpec, swIfIndex)
		}
		swIfIndex, _ = podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		s.UnroutePodInterface(swIfIndex)
	}

	s.UnroutePodVRF(podSpec)

	/* Interfaces */
	if podSpec.EnableVCL {
		s.vclDriver.DeleteInterface(podSpec)
	}

	if podSpec.EnableMemif {
		s.memifDriver.DeleteInterface(podSpec)
	}

	containerIPs := s.tuntapDriver.DeleteInterface(podSpec)
	for _, containerIP := range containerIPs {
		s.routingServer.AnnounceLocalAddress(&containerIP, true /* isWithdrawal */)
	}

    s.loopbackDriver.DeleteInterface(podSpec)

	err = s.vpp.DelDefault46RouteViaTable(podSpec.VrfId, common.PodVRFIndex)
	if err != nil {
		s.log.Errorf("Error deleting default route to VRF %s", err)
	}

	err = s.vpp.DelVRF46(podSpec.VrfId, getInterfaceVrfName(podSpec))
	if err != nil {
		s.log.Errorf("Error deleting VRF %s", err)
	}
	vpplink.FreeID(podVrfAllocator, podSpec.VrfId)
}
