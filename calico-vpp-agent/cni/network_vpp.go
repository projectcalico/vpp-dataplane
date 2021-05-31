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
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
)

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *storage.LocalPodSpec, doHostSideConf bool) (swIfIndex uint32, err error) {
	if podSpec.NetnsName == "" {
		s.log.Infof("no netns passed, skipping")
		return 0, nil
	}

	podSpec.NeedsSnat = false
	for _, containerIP := range podSpec.GetContainerIps() {
		podSpec.NeedsSnat = podSpec.NeedsSnat || s.IPNetNeedsSNAT(containerIP)
	}

	s.log.Infof("Creating container interface using VPP networking")
	swIfIndex, err = s.tuntapDriver.Create(podSpec, doHostSideConf)
	if err != nil {
		goto err1
	}

	_, err = s.memifDriver.Create(podSpec)
	if err != nil {
		goto err2
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		s.routingServer.AnnounceLocalAddress(containerIP, false /* isWithdrawal */)
	}

	s.policyServer.WorkloadAdded(&policy.WorkloadEndpointID{
		OrchestratorID: podSpec.OrchestratorID,
		WorkloadID:     podSpec.WorkloadID,
		EndpointID:     podSpec.EndpointID,
	}, swIfIndex)

	return swIfIndex, err

err2:
	s.memifDriver.Delete(podSpec)
err1:
	_ = s.tuntapDriver.Delete(podSpec)
	return 0, errors.Wrapf(err, "Error creating interface")

}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(podSpec *storage.LocalPodSpec) {
	// Only try to delete the device if a namespace was passed in.
	if podSpec.NetnsName == "" {
		s.log.Infof("no netns passed, skipping")
		return
	}

	containerIPs := s.tuntapDriver.Delete(podSpec)
	for _, containerIP := range containerIPs {
		s.routingServer.AnnounceLocalAddress(&containerIP, true /* isWithdrawal */)
	}

	s.memifDriver.Delete(podSpec)
}
