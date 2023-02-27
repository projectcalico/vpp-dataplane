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
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type PodNSNotFoundErr struct {
	ns string
}

func (e PodNSNotFoundErr) Error() string {
	return fmt.Sprintf("Netns '%s' doesn't exist, skipping", e.ns)
}

type NetworkPod struct {
	NetworkVni  uint32
	ContainerIP *net.IPNet
}

func (s *Server) checkAvailableBuffers(podSpec *storage.LocalPodSpec) error {
	podBuffers := podSpec.GetBuffersNeeded()
	buffers := podBuffers
	existingPods := uint64(len(s.podInterfaceMap))
	for _, existingPodSpec := range s.podInterfaceMap {
		buffers += existingPodSpec.GetBuffersNeeded()
	}
	s.log.Infof("pod(add) checking available buffers, %d existing pods, request for this pod: %d, total request: %d / %d", existingPods, podBuffers, buffers, s.availableBuffers)
	if buffers > s.availableBuffers {
		return errors.Errorf("Cannot create interface: Out of buffers: available buffers = %d, buffers needed = %d. "+
			"Increase buffers-per-numa in the VPP configuration or reduce CALICOVPP_TAP_RING_SIZE to allow more "+
			"pods to be scheduled. Limit the number of pods per node to prevent this error", s.availableBuffers, buffers)
	}
	return nil
}

func (s *Server) findPodVRFs(podSpec *storage.LocalPodSpec) bool {
	podSpec.V4VrfId = types.InvalidID
	podSpec.V6VrfId = types.InvalidID

	vrfs, err := s.vpp.ListVRFs()
	if err != nil {
		s.log.Errorf("Error listing VRFs %s", err)
		return false
	}

	for _, vrf := range vrfs {
		for _, ipFamily := range vpplink.IpFamilies {
			if vrf.Name == podSpec.GetVrfTag(ipFamily, "") {
				podSpec.SetVrfId(vrf.VrfID, ipFamily)
			}
		}
		if podSpec.V4VrfId != types.InvalidID && podSpec.V6VrfId != types.InvalidID {
			return true
		}
	}

	if (podSpec.V4VrfId != types.InvalidID) != (podSpec.V6VrfId != types.InvalidID) {
		s.log.Errorf("Partial VRF state v4=%d v6=%d key=%s", podSpec.V4VrfId, podSpec.V6VrfId, podSpec.Key())
	}

	return false
}

func (s *Server) removeConflictingContainers(newAddresses []storage.LocalIP, networkName string) {
	addrMap := make(map[string]storage.LocalPodSpec)
	for _, podSpec := range s.podInterfaceMap {
		for _, addr := range podSpec.ContainerIps {
			if podSpec.NetworkName == networkName {
				addrMap[addr.IP.String()] = podSpec
			}
		}
	}
	podSpecsToDelete := make(map[string]storage.LocalPodSpec)
	for _, newAddr := range newAddresses {
		podSpec, found := addrMap[newAddr.IP.String()]
		if found {
			s.log.Warnf("podSpec conflict newAddr=%s, podSpec=%s", newAddr, podSpec.String())
			podSpecsToDelete[podSpec.Key()] = podSpec
		}
	}
	for _, podSpec := range podSpecsToDelete {
		s.log.Infof("Deleting conflicting podSpec=%s", podSpec.Key())
		s.DelVppInterface(&podSpec)
		delete(s.podInterfaceMap, podSpec.Key())
		err := storage.PersistCniServerState(s.podInterfaceMap, config.CniServerStateFile+fmt.Sprint(storage.CniServerStateFileVersion))
		if err != nil {
			s.log.Errorf("CNI state persist errored %v", err)
		}
	}
}

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *storage.LocalPodSpec, doHostSideConf bool) (tunTapSwIfIndex uint32, err error) {
	podSpec.NeedsSnat = false
	for _, containerIP := range podSpec.GetContainerIps() {
		podSpec.NeedsSnat = podSpec.NeedsSnat || s.policyServerIpam.IPNetNeedsSNAT(containerIP)
	}

	err = ns.IsNSorErr(podSpec.NetnsName)
	if err != nil {
		return vpplink.InvalidID, PodNSNotFoundErr{podSpec.NetnsName}
	}

	if podSpec.NetworkName != "" {
		s.log.Infof("Checking network exists")
		_, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			s.log.Errorf("network %s does not exist", podSpec.NetworkName)
			return vpplink.InvalidID, errors.Errorf("network %s does not exist", podSpec.NetworkName)
		}
	}
	/**
	 * Check if the VRFs already exist in VPP,
	 * if yes we postulate the pod is already well setup
	 */
	if s.findPodVRFs(podSpec) {
		s.log.Infof("VRF already exists in VPP podSpec=%s", podSpec.Key())
		return podSpec.TunTapSwIfIndex, nil
	}

	/**
	 * Do we already have a pod with this address in VPP ?
	 * in this case, clean it up otherwise on the other pod's
	 * deletion our route in the main VRF will be removed
	 *
	 * As we did not find the VRF in VPP, we shouldn't find
	 * ourselves in s.podInterfaceMap
	 */
	s.removeConflictingContainers(podSpec.ContainerIps, podSpec.NetworkName)

	stack := s.vpp.NewCleanupStack()
	var vni uint32
	err = s.checkAvailableBuffers(podSpec)
	if err != nil {
		goto err
	}

	s.log.Infof("pod(add) VRF")
	err = s.CreatePodVRF(podSpec, stack)
	if err != nil {
		goto err
	}

	s.log.Infof("pod(add) loopback")
	err = s.loopbackDriver.CreateInterface(podSpec, stack)
	if err != nil {
		goto err
	}

	if podSpec.NetworkName == "" || !podSpec.EnableMemif { // The only case where tun is not created is when we create memif interface in non main network
		s.log.Infof("pod(add) tuntap")
		err = s.tuntapDriver.CreateInterface(podSpec, stack, doHostSideConf)
		if err != nil {
			goto err
		}
	}

	if podSpec.EnableMemif && *config.GetCalicoVppFeatureGates().MemifEnabled {
		s.log.Infof("pod(add) memif")
		err = s.memifDriver.CreateInterface(podSpec, stack, doHostSideConf)
		if err != nil {
			goto err
		}
	}

	if podSpec.EnableVCL && *config.GetCalicoVppFeatureGates().VCLEnabled {
		s.log.Infof("pod(add) VCL socket")
		err = s.vclDriver.CreateInterface(podSpec, stack)
		if err != nil {
			goto err
		}
	}

	/* Routes */
	if podSpec.EnableVCL {
		s.log.Infof("pod(add) Punt routes")
		err = s.SetupPuntRoutes(podSpec, stack, podSpec.TunTapSwIfIndex)
		if err != nil {
			goto err
		}
		err = s.CreateVRFRoutesToPod(podSpec, stack)
		if err != nil {
			goto err
		}
	} else {
		swIfIndex, isL3 := podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		if swIfIndex != types.InvalidID {
			s.log.Infof("pod(add) Default routes to swIfIndex=%d isL3=%t", swIfIndex, isL3)
			err = s.RoutePodInterface(podSpec, stack, swIfIndex, isL3)
			if err != nil {
				goto err
			}
		} else {
			s.log.Warn("No default if type for pod")
		}

		swIfIndex, isL3 = podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if swIfIndex != types.InvalidID {
			s.log.Infof("pod(add) PBL routes to %d l3?:%t", swIfIndex, isL3)
			err = s.RoutePblPortsPodInterface(podSpec, stack, swIfIndex, isL3)
			if err != nil {
				goto err
			}
		}
	}

	if podSpec.NetworkName != "" {
		value, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			s.log.Errorf("network not found %s", podSpec.NetworkName)
		} else {
			vni = value.(*watchers.NetworkDefinition).Vni
		}
	}

	s.log.Infof("pod(add) announcing pod Addresses")
	for _, containerIP := range podSpec.GetContainerIps() {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.LocalPodAddressAdded,
			New:  NetworkPod{ContainerIP: containerIP, NetworkVni: vni},
		})
	}

	s.log.Infof("pod(add) HostPorts")
	err = s.AddHostPort(podSpec, stack)
	if err != nil {
		goto err
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PodAdded,
		New:  podSpec,
	})
	if podSpec.NetworkName != "" && podSpec.EnableMemif {
		return podSpec.MemifSwIfIndex, err
	}

	s.log.Infof("pod(add) activate strict RPF on interface")
	err = s.ActivateStrictRPF(podSpec, stack)
	if err != nil {
		s.log.Errorf("failed to activate rpf strict on interface : %s", err)
		goto err
	}
	return podSpec.TunTapSwIfIndex, err

err:
	s.log.Errorf("Error, try a cleanup %+v", err)
	stack.Execute()
	return vpplink.InvalidID, errors.Wrapf(err, "Error creating interface")

}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(podSpec *storage.LocalPodSpec) {
	err := ns.IsNSorErr(podSpec.NetnsName)
	if err != nil {
		s.log.Infof("pod(del) netns '%s' doesn't exist, skipping", podSpec.NetnsName)
		return
	}

	/* At least one VRF does not exist in VPP, still try removing */
	if !s.findPodVRFs(podSpec) {
		s.log.Warnf("pod(del) VRF for netns '%s' doesn't exist, skipping", podSpec.NetnsName)
		return
	}

	s.DelHostPort(podSpec)

	var vni uint32
	deleteLocalPodAddress := true
	if podSpec.NetworkName != "" {
		value, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			deleteLocalPodAddress = false
		} else {
			vni = value.(*watchers.NetworkDefinition).Vni
		}
	}
	if deleteLocalPodAddress {
		for _, containerIP := range podSpec.GetContainerIps() {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.LocalPodAddressDeleted,
				Old:  NetworkPod{ContainerIP: containerIP, NetworkVni: vni},
			})

		}
	}

	/* Routes */
	if podSpec.EnableVCL {
		if podSpec.TunTapSwIfIndex != vpplink.InvalidID {
			s.log.Infof("pod(del) routes to podVRF")
			s.DeleteVRFRoutesToPod(podSpec)
			s.log.Infof("pod(del) punt routes")
			s.RemovePuntRoutes(podSpec, podSpec.TunTapSwIfIndex)
		}
	} else {
		swIfIndex, _ := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if swIfIndex != types.InvalidID {
			s.log.Infof("pod(del) PBL routes to %d", swIfIndex)
			s.UnroutePblPortsPodInterface(podSpec, swIfIndex)
		}
		swIfIndex, _ = podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		if swIfIndex != types.InvalidID {
			s.log.Infof("pod(del) default routes to %d", swIfIndex)
			s.UnroutePodInterface(podSpec, swIfIndex)
		}
	}

	/* RPF */
	s.log.Infof("pod(del) RPF VRF")
	s.DeactivateStrictRPF(podSpec)

	/* Interfaces */
	if podSpec.EnableVCL && *config.GetCalicoVppFeatureGates().VCLEnabled {
		s.log.Infof("pod(del) VCL")
		s.vclDriver.DeleteInterface(podSpec)
	}
	if podSpec.EnableMemif && *config.GetCalicoVppFeatureGates().MemifEnabled {
		s.log.Infof("pod(del) memif")
		s.memifDriver.DeleteInterface(podSpec)
	}
	s.log.Infof("pod(del) tuntap")
	s.tuntapDriver.DeleteInterface(podSpec)
	s.log.Infof("pod(del) loopback")
	s.loopbackDriver.DeleteInterface(podSpec)

	s.log.Infof("pod(del) VRF")
	s.DeletePodVRF(podSpec)
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PodDeleted,
		Old:  podSpec,
	})
}
