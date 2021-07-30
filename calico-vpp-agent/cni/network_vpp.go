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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
)

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *storage.LocalPodSpec, doHostSideConf bool) (tunTapSwIfIndex uint32, err error) {
	podSpec.NeedsSnat = false
	for _, containerIP := range podSpec.GetContainerIps() {
		podSpec.NeedsSnat = podSpec.NeedsSnat || s.IPNetNeedsSNAT(containerIP)
	}

    err = s.vpp.AddVRF46(podSpec.VrfId, fmt.Sprintf("pod-%s-table", podSpec.Key()))
    if err != nil {
            goto err0
    }
    err = s.vpp.AddDefault46RouteViaTable(podSpec.VrfId, common.DefaultVRFIndex)
    if err != nil {
            goto err0
    }

	s.log.Infof("Creating container interface using VPP networking")
	tunTapSwIfIndex, err = s.tuntapDriver.Create(podSpec, doHostSideConf)
	if err != nil {
		goto err1
	}

	if podSpec.HasIfType(storage.VppMemif) {
		s.log.Infof("Creating container memif interface")
		_, err = s.memifDriver.Create(podSpec)
		if err != nil {
			goto err2
		}
	}

	if podSpec.HasIfType(storage.VppVcl) {
		s.log.Infof("Enabling container VCL")
		err = s.vclDriver.Create(podSpec, tunTapSwIfIndex)
		if err != nil {
			goto err3
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

err3:
	s.vclDriver.Delete(podSpec)
err2:
	s.memifDriver.Delete(podSpec)
err1:
	_ = s.tuntapDriver.Delete(podSpec)
err0:
	// TODO : delete VRF
	return tunTapSwIfIndex, errors.Wrapf(err, "Error creating interface")

}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(podSpec *storage.LocalPodSpec) {
	containerIPs := s.tuntapDriver.Delete(podSpec)
	for _, containerIP := range containerIPs {
		s.routingServer.AnnounceLocalAddress(&containerIP, true /* isWithdrawal */)
	}
	// TODO : delete VRF

	s.memifDriver.Delete(podSpec)
	s.vclDriver.Delete(podSpec)
}
