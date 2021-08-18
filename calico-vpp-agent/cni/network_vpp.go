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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func getInterfaceVrfName(podSpec *storage.LocalPodSpec, suffix string) string {
	return fmt.Sprintf("pod-%s-table-%s", podSpec.Key(), suffix)
}

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *storage.LocalPodSpec, doHostSideConf bool) (tunTapSwIfIndex uint32, err error) {
	podSpec.NeedsSnat = false
	for _, containerIP := range podSpec.GetContainerIps() {
		podSpec.NeedsSnat = podSpec.NeedsSnat || s.IPNetNeedsSNAT(containerIP)
	}

	stack := s.vpp.NewCleanupStack()

	err = s.CreateVRFandRoutesToPod(podSpec, stack)
	if err != nil {
		goto err
	}

	err = s.loopbackDriver.CreateInterface(podSpec, stack)
	if err != nil {
		goto err
	}

	s.log.Infof("Creating container interface using VPP networking")
	err = s.tuntapDriver.CreateInterface(podSpec, stack, doHostSideConf)
	if err != nil {
		goto err
	}

	if podSpec.EnableMemif && config.MemifEnabled {
		s.log.Infof("Creating container memif interface")
		err := s.memifDriver.CreateInterface(podSpec, stack)
		if err != nil {
			goto err
		}
	}

	if podSpec.EnableVCL && config.VCLEnabled {
		s.log.Infof("Enabling container VCL")
		err = s.vclDriver.CreateInterface(podSpec, stack)
		if err != nil {
			goto err
		}
	}

	err = s.SetupPuntRoutes(podSpec, stack, podSpec.TunTapSwIfIndex)
	if err != nil {
		goto err
	}

	/* Routes */
	if !podSpec.EnableVCL {
		swIfIndex, isL3 := podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		if swIfIndex != types.InvalidID {
			err = s.RoutePodInterface(podSpec, stack, swIfIndex, isL3)
			if err != nil {
				goto err
			}
		} else {
			s.log.Warn("No default if type for pod")
		}

		swIfIndex, isL3 = podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if swIfIndex != types.InvalidID {
			err = s.RoutePblPortsPodInterface(podSpec, stack, podSpec.MemifSwIfIndex, isL3)
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
	}, podSpec.TunTapSwIfIndex)

	return podSpec.TunTapSwIfIndex, err

err:
	stack.Execute()
	return vpplink.InvalidID, errors.Wrapf(err, "Error creating interface")

}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(podSpec *storage.LocalPodSpec) {
	/* Routes */
	if !podSpec.EnableVCL {
		swIfIndex, _ := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if swIfIndex != types.InvalidID {
			s.UnroutePblPortsPodInterface(podSpec, swIfIndex)
		}
		swIfIndex, _ = podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		if swIfIndex != types.InvalidID {
			s.UnroutePodInterface(podSpec, swIfIndex)
		}
	}

	if podSpec.TunTapSwIfIndex != vpplink.InvalidID {
		s.RemovePuntRoutes(podSpec, podSpec.TunTapSwIfIndex)
	}

	/* Interfaces */
	s.vclDriver.DeleteInterface(podSpec)
	s.memifDriver.DeleteInterface(podSpec)
	s.tuntapDriver.DeleteInterface(podSpec)

	for _, containerIP := range podSpec.GetContainerIps() {
		s.routingServer.AnnounceLocalAddress(&containerIP, true /* isWithdrawal */)
	}

	s.loopbackDriver.DeleteInterface(podSpec)

	s.DeleteVRFandRoutesToPod(podSpec)
}
