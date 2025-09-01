// Copyright (C) 2025 Cisco Systems Inc.
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

package policies

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/pkg/errors"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// Server holds all the data required to configure the policies defined by felix in VPP
type PoliciesHandler struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	endpointsInterfaces map[WorkloadEndpointID]map[string]uint32
	tunnelSwIfIndexes   map[uint32]bool
	interfacesMap       map[string]interfaceDetails

	configuredState *PolicyState
	pendingState    *PolicyState

	state common.FelixSocketSyncState

	/* failSafe policies allow traffic on some ports irrespective of the policy */
	failSafePolicy *Policy
	/* workloadToHost may drop traffic that goes from the pods to the host */
	workloadsToHostPolicy  *Policy
	defaultTap0IngressConf []uint32
	/* always allow traffic coming from host to the pods (for healthchecks and so on) */
	// AllowFromHostPolicy persists the policy allowing host --> pod communications.
	// See CreateAllowFromHostPolicy definition
	AllowFromHostPolicy *Policy
	// allPodsIpset persists the ipset containing all the workload endpoints (pods) addresses
	allPodsIpset *IPSet
	/* allow traffic between uplink/tunnels and tap interfaces */
	allowToHostPolicy *Policy
}

func (s *PoliciesHandler) GetState() *PolicyState {
	if s.state.IsPending() {
		return s.pendingState
	}
	return s.configuredState
}

func NewPoliciesHandler(vpp *vpplink.VppLink, cache *cache.Cache, clientv3 calicov3cli.Interface, log *logrus.Entry) *PoliciesHandler {
	return &PoliciesHandler{
		log:                 log,
		vpp:                 vpp,
		cache:               cache,
		endpointsInterfaces: make(map[WorkloadEndpointID]map[string]uint32),
		tunnelSwIfIndexes:   make(map[uint32]bool),

		configuredState: NewPolicyState(),
		pendingState:    NewPolicyState(),
		state:           common.StateDisconnected,
	}
}

func protoPortListEqual(a, b []felixConfig.ProtoPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i, elemA := range a {
		elemB := b[i]
		if elemA.Net != elemB.Net {
			return false
		}
		if elemA.Protocol != elemB.Protocol {
			return false
		}
		if elemA.Port != elemB.Port {
			return false
		}
	}
	return true
}

func (s *PoliciesHandler) OnInSync(msg *proto.InSync) (err error) {
	if s.state != common.StateSyncing {
		return fmt.Errorf("received InSync but state was not syncing")
	}

	s.state = common.StateInSync
	s.log.Infof("Policies now in sync")
	return s.applyPendingState()
}

func (s *PoliciesHandler) OnIpsetUpdate(msg *proto.IPSetUpdate) (err error) {
	ips, err := FromIPSetUpdate(msg)
	if err != nil {
		return errors.Wrap(err, "cannot process IPSetUpdate")
	}
	state := s.GetState()
	_, ok := state.IPSets[msg.GetId()]
	if ok {
		return fmt.Errorf("received new ipset for ID %s that already exists", msg.GetId())
	}
	if !s.state.IsPending() {
		err = ips.Create(s.vpp)
		if err != nil {
			return errors.Wrapf(err, "cannot create ipset %s", msg.GetId())
		}
	}
	state.IPSets[msg.GetId()] = ips
	s.log.Debugf("Handled Ipset Update pending=%t id=%s %s", s.state.IsPending(), msg.GetId(), ips)
	return nil
}

func (s *PoliciesHandler) OnIpsetDeltaUpdate(msg *proto.IPSetDeltaUpdate) (err error) {
	ips, ok := s.GetState().IPSets[msg.GetId()]
	if !ok {
		return fmt.Errorf("received delta update for non-existent ipset")
	}
	err = ips.AddMembers(msg.GetAddedMembers(), !s.state.IsPending(), s.vpp)
	if err != nil {
		return errors.Wrap(err, "cannot process ipset delta update")
	}
	err = ips.RemoveMembers(msg.GetRemovedMembers(), !s.state.IsPending(), s.vpp)
	if err != nil {
		return errors.Wrap(err, "cannot process ipset delta update")
	}
	s.log.Debugf("Handled Ipset delta Update pending=%t id=%s %s", s.state.IsPending(), msg.GetId(), ips)
	return nil
}

func (s *PoliciesHandler) OnIpsetRemove(msg *proto.IPSetRemove) (err error) {
	state := s.GetState()
	ips, ok := state.IPSets[msg.GetId()]
	if !ok {
		s.log.Warnf("Received ipset delete for ID %s that doesn't exists", msg.GetId())
		return nil
	}
	if !s.state.IsPending() {
		err = ips.Delete(s.vpp)
		if err != nil {
			return errors.Wrapf(err, "cannot delete ipset %s", msg.GetId())
		}
	}
	s.log.Debugf("Handled Ipset remove pending=%t id=%s %s", s.state.IsPending(), msg.GetId(), ips)
	delete(state.IPSets, msg.GetId())
	return nil
}

func (s *PoliciesHandler) OnActivePolicyUpdate(msg *proto.ActivePolicyUpdate) (err error) {
	state := s.GetState()
	id := PolicyID{
		Tier: msg.Id.Tier,
		Name: msg.Id.Name,
	}
	p, err := FromProtoPolicy(msg.Policy, "")
	if err != nil {
		return errors.Wrapf(err, "cannot process policy update")
	}

	s.log.Infof("Handling ActivePolicyUpdate pending=%t id=%s %s", s.state.IsPending(), id, p)
	existing, ok := state.Policies[id]
	if ok { // Policy with this ID already exists
		if s.state.IsPending() {
			// Just replace policy in pending state
			state.Policies[id] = p
		} else {
			err := existing.Update(s.vpp, p, state)
			if err != nil {
				return errors.Wrap(err, "cannot update policy")
			}
		}
	} else {
		// Create it in state
		state.Policies[id] = p
		if !s.state.IsPending() {
			err := p.Create(s.vpp, state)
			if err != nil {
				return errors.Wrap(err, "cannot create policy")
			}
		}
	}

	for network := range s.cache.NetworkDefinitions {
		id := PolicyID{
			Tier:    msg.Id.Tier,
			Name:    msg.Id.Name,
			Network: network,
		}
		p, err := FromProtoPolicy(msg.Policy, network)
		if err != nil {
			return errors.Wrapf(err, "cannot process policy update")
		}

		s.log.Infof("Handling ActivePolicyUpdate pending=%t id=%s %s", s.state.IsPending(), id, p)

		existing, ok := state.Policies[id]
		if ok { // Policy with this ID already exists
			if s.state.IsPending() {
				// Just replace policy in pending state
				state.Policies[id] = p
			} else {
				err := existing.Update(s.vpp, p, state)
				if err != nil {
					return errors.Wrap(err, "cannot update policy")
				}
			}
		} else {
			// Create it in state
			state.Policies[id] = p
			if !s.state.IsPending() {
				err := p.Create(s.vpp, state)
				if err != nil {
					return errors.Wrap(err, "cannot create policy")
				}
			}
		}

	}
	return nil
}

func (s *PoliciesHandler) OnActivePolicyRemove(msg *proto.ActivePolicyRemove) (err error) {
	state := s.GetState()
	id := PolicyID{
		Tier: msg.Id.Tier,
		Name: msg.Id.Name,
	}
	s.log.Infof("policy(del) Handling ActivePolicyRemove pending=%t id=%s", s.state.IsPending(), id)

	for policyID := range state.Policies {
		if policyID.Name == id.Name && policyID.Tier == id.Tier {
			existing, ok := state.Policies[policyID]
			if !ok {
				s.log.Warnf("Received policy delete for Tier %s Name %s that doesn't exists", id.Tier, id.Name)
				return nil
			}
			if !s.state.IsPending() {
				err = existing.Delete(s.vpp, state)
				if err != nil {
					return errors.Wrap(err, "error deleting policy")
				}
			}
			delete(state.Policies, policyID)
		}
	}
	return nil
}

func (s *PoliciesHandler) OnActiveProfileUpdate(msg *proto.ActiveProfileUpdate) (err error) {
	state := s.GetState()
	id := msg.Id.Name
	p, err := FromProtoProfile(msg.Profile)
	if err != nil {
		return errors.Wrapf(err, "cannot process profile update")
	}

	existing, ok := state.Profiles[id]
	if ok { // Policy with this ID already exists
		if s.state.IsPending() {
			// Just replace policy in pending state
			state.Profiles[id] = p
		} else {
			err := existing.Update(s.vpp, p, state)
			if err != nil {
				return errors.Wrap(err, "cannot update profile")
			}
		}
	} else {
		// Create it in state
		state.Profiles[id] = p
		if !s.state.IsPending() {
			err := p.Create(s.vpp, state)
			if err != nil {
				return errors.Wrap(err, "cannot create profile")
			}
		}
	}
	s.log.Infof("policy(upd) Handled Profile Update pending=%t id=%s existing=%s new=%s", s.state.IsPending(), id, existing, p)
	return nil
}

func (s *PoliciesHandler) OnActiveProfileRemove(msg *proto.ActiveProfileRemove) (err error) {
	state := s.GetState()
	id := msg.Id.Name
	existing, ok := state.Profiles[id]
	if !ok {
		s.log.Warnf("Received profile delete for Name %s that doesn't exists", id)
		return nil
	}
	if !s.state.IsPending() {
		err = existing.Delete(s.vpp, state)
		if err != nil {
			return errors.Wrap(err, "error deleting profile")
		}
	}
	s.log.Infof("policy(del) Handled Profile Remove pending=%t id=%s policy=%s", s.state.IsPending(), id, existing)
	delete(state.Profiles, id)
	return nil
}

func (s *PoliciesHandler) getAllTunnelSwIfIndexes() (swIfIndexes []uint32) {
	swIfIndexes = make([]uint32, 0)
	for k := range s.tunnelSwIfIndexes {
		swIfIndexes = append(swIfIndexes, k)
	}
	return swIfIndexes
}

func (s *PoliciesHandler) OnHostEndpointUpdate(msg *proto.HostEndpointUpdate) (err error) {
	state := s.GetState()
	id := FromProtoHostEndpointID(msg.Id)
	hep, err := FromProtoHostEndpoint(msg.Endpoint)
	if err != nil {
		return err
	}
	if hep.InterfaceName != "" && hep.InterfaceName != "*" {
		interfaceDetails, found := s.interfacesMap[hep.InterfaceName]
		if found {
			hep.UplinkSwIfIndexes = append(hep.UplinkSwIfIndexes, interfaceDetails.uplinkIndex)
			hep.TapSwIfIndexes = append(hep.TapSwIfIndexes, interfaceDetails.tapIndex)
		} else {
			// we are not supposed to fallback to expectedIPs if interfaceName doesn't match
			// this is the current behavior in calico linux
			s.log.Errorf("cannot find host endpoint: interface named %s does not exist", hep.InterfaceName)
		}
	} else if hep.InterfaceName == "" && hep.ExpectedIPs != nil {
		for _, existingIf := range s.interfacesMap {
		interfaceFound:
			for _, address := range existingIf.addresses {
				for _, expectedIP := range hep.ExpectedIPs {
					if address == expectedIP {
						hep.UplinkSwIfIndexes = append(hep.UplinkSwIfIndexes, existingIf.uplinkIndex)
						hep.TapSwIfIndexes = append(hep.TapSwIfIndexes, existingIf.tapIndex)
						break interfaceFound
					}
				}
			}
		}
	} else if hep.InterfaceName == "*" {
		for _, interfaceDetails := range s.interfacesMap {
			hep.UplinkSwIfIndexes = append(hep.UplinkSwIfIndexes, interfaceDetails.uplinkIndex)
			hep.TapSwIfIndexes = append(hep.TapSwIfIndexes, interfaceDetails.tapIndex)
		}
	}
	hep.TunnelSwIfIndexes = s.getAllTunnelSwIfIndexes()
	if len(hep.UplinkSwIfIndexes) == 0 || len(hep.TapSwIfIndexes) == 0 {
		s.log.Warnf("No interface in vpp for host endpoint id=%s hep=%s", id.EndpointID, hep.String())
		return nil
	}

	existing, found := state.HostEndpoints[*id]
	if found {
		if s.state.IsPending() {
			hep.CurrentForwardConf = existing.CurrentForwardConf
			state.HostEndpoints[*id] = hep
		} else {
			err := s.UpdateHostEndpoint(existing, hep, state)
			if err != nil {
				return errors.Wrap(err, "cannot update host endpoint")
			}
		}
		s.log.Infof("policy(upd) Updating host endpoint id=%s found=%t existing=%s new=%s", *id, found, existing, hep)
	} else {
		state.HostEndpoints[*id] = hep
		if !s.state.IsPending() {
			err := s.CreateHostEndpoint(hep, state)
			if err != nil {
				return errors.Wrap(err, "cannot create host endpoint")
			}
		}
		s.log.Infof("policy(add) Updating host endpoint id=%s found=%t new=%s", *id, found, hep)
	}
	return nil
}

func (s *PoliciesHandler) OnHostEndpointRemove(msg *proto.HostEndpointRemove) (err error) {
	state := s.GetState()
	id := FromProtoHostEndpointID(msg.Id)
	existing, ok := state.HostEndpoints[*id]
	if !ok {
		s.log.Warnf("Received host endpoint delete for id=%s that doesn't exists", id)
		return nil
	}
	if !s.state.IsPending() && len(existing.UplinkSwIfIndexes) != 0 {
		err = s.DeleteHostEndpoint(existing, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "error deleting host endpoint")
		}
	}
	s.log.Infof("policy(del) Handled Host Endpoint Remove pending=%t id=%s %s", s.state.IsPending(), id, existing)
	delete(state.HostEndpoints, *id)
	return nil
}

func (s *PoliciesHandler) getAllWorkloadEndpointIdsFromUpdate(msg *proto.WorkloadEndpointUpdate) []*WorkloadEndpointID {
	id := FromProtoEndpointID(msg.Id)
	idsNetworks := []*WorkloadEndpointID{id}
	netStatusesJSON, found := msg.Endpoint.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !found {
		s.log.Infof("no network status for pod, no multiple networks")
	} else {
		var netStatuses []nettypes.NetworkStatus
		err := json.Unmarshal([]byte(netStatusesJSON), &netStatuses)
		if err != nil {
			s.log.Error(err)
		}
		for _, networkStatus := range netStatuses {
			for netDefName, netDef := range s.cache.NetworkDefinitions {
				if networkStatus.Name == netDef.NetAttachDefs {
					id := &WorkloadEndpointID{OrchestratorID: id.OrchestratorID, WorkloadID: id.WorkloadID, EndpointID: id.EndpointID, Network: netDefName}
					idsNetworks = append(idsNetworks, id)
				}
			}
		}
	}
	return idsNetworks
}

func (s *PoliciesHandler) OnTunnelAdded(swIfIndex uint32) {
	s.tunnelSwIfIndexes[swIfIndex] = true
	state := s.GetState()
	for _, h := range state.HostEndpoints {
		err := s.handleTunnelChange(h, swIfIndex, true /* isAdd */, s.state.IsPending())
		if err != nil {
			s.log.Errorf("error in handleTunnelChange %v", err)
		}
	}
}
func (s *PoliciesHandler) OnTunnelDelete(swIfIndex uint32) {

	delete(s.tunnelSwIfIndexes, swIfIndex)

	state := s.GetState()
	for _, h := range state.HostEndpoints {
		err := s.handleTunnelChange(h, swIfIndex, false /* isAdd */, s.state.IsPending())
		if err != nil {
			s.log.Errorf("error in handleTunnelChange %v", err)
		}
	}
}

func (s *PoliciesHandler) OnWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) (err error) {
	state := s.GetState()
	idsNetworks := s.getAllWorkloadEndpointIdsFromUpdate(msg)
	for _, id := range idsNetworks {
		wep := FromProtoWorkload(msg.Endpoint)
		existing, found := state.WorkloadEndpoints[*id]
		swIfIndexMap, swIfIndexFound := s.endpointsInterfaces[*id]

		if found {
			if s.state.IsPending() || !swIfIndexFound {
				state.WorkloadEndpoints[*id] = wep
				s.log.Infof("policy(upd) Workload Endpoint Update pending=%t id=%s existing=%s new=%s swIf=??", s.state.IsPending(), *id, existing, wep)
			} else {
				err := s.UpdateWorkloadEndpoint(existing, wep, state, id.Network)
				if err != nil {
					return errors.Wrap(err, "cannot update workload endpoint")
				}
				s.log.Infof("policy(upd) Workload Endpoint Update pending=%t id=%s existing=%s new=%s swIf=%v", s.state.IsPending(), *id, existing, wep, swIfIndexMap)
			}
		} else {
			state.WorkloadEndpoints[*id] = wep
			if !s.state.IsPending() && swIfIndexFound {
				swIfIndexList := []uint32{}
				for _, idx := range swIfIndexMap {
					swIfIndexList = append(swIfIndexList, idx)
				}
				err := s.CreateWorkloadEndpoint(wep, swIfIndexList, state, id.Network)
				if err != nil {
					return errors.Wrap(err, "cannot create workload endpoint")
				}
				s.log.Infof("policy(add) Workload Endpoint add pending=%t id=%s new=%s swIf=%v", s.state.IsPending(), *id, wep, swIfIndexMap)
			} else {
				s.log.Infof("policy(add) Workload Endpoint add pending=%t id=%s new=%s swIf=??", s.state.IsPending(), *id, wep)
			}
		}
	}
	return nil
}

func (s *PoliciesHandler) OnWorkloadEndpointRemove(msg *proto.WorkloadEndpointRemove) (err error) {
	state := s.GetState()
	id := FromProtoEndpointID(msg.Id)
	existing, ok := state.WorkloadEndpoints[*id]
	if !ok {
		s.log.Warnf("Received workload endpoint delete for %v that doesn't exists", id)
		return nil
	}
	if !s.state.IsPending() && len(existing.SwIfIndex) != 0 {
		err = s.DeleteWorkloadEndpoint(existing)
		if err != nil {
			return errors.Wrap(err, "error deleting workload endpoint")
		}
	}
	s.log.Infof("policy(del) Handled Workload Endpoint Remove pending=%t id=%s existing=%s", s.state.IsPending(), *id, existing)
	delete(state.WorkloadEndpoints, *id)
	for existingID := range state.WorkloadEndpoints {
		if existingID.OrchestratorID == id.OrchestratorID && existingID.WorkloadID == id.WorkloadID {
			if !s.state.IsPending() && len(existing.SwIfIndex) != 0 {
				err = s.DeleteWorkloadEndpoint(existing)
				if err != nil {
					return errors.Wrap(err, "error deleting workload endpoint")
				}
			}
			s.log.Infof("policy(del) Handled Workload Endpoint Remove pending=%t id=%s existing=%s", s.state.IsPending(), existingID, existing)
			delete(state.WorkloadEndpoints, existingID)
		}
	}
	return nil
}

func (s *PoliciesHandler) OnFelixSocketStateChanged(evt *common.FelixSocketStateChanged) {
	s.state = evt.NewState
}

func (s *PoliciesHandler) OnFelixConfChanged(old, new *felixConfig.Config) {
	if s.state != common.StateConnected {
		s.log.Errorf("received ConfigUpdate but server is not in Connected state! state: %v", s.state)
		return
	}
	s.state = common.StateSyncing
	if s.cache.FelixConfig.DefaultEndpointToHostAction != old.DefaultEndpointToHostAction {
		s.log.Infof("Change in EndpointToHostAction to %+v", s.getEndpointToHostAction())
		workloadsToHostAllowRule := &Rule{
			VppID: types.InvalidID,
			Rule: &types.Rule{
				Action: s.getEndpointToHostAction(),
			},
			SrcIPSetNames: []string{"calico-vpp-wep-addr-ipset"},
		}
		policy := s.workloadsToHostPolicy.DeepCopy()
		policy.InboundRules = []*Rule{workloadsToHostAllowRule}
		err := s.workloadsToHostPolicy.Update(s.vpp, policy,
			&PolicyState{
				IPSets: map[string]*IPSet{
					"calico-vpp-wep-addr-ipset": s.allPodsIpset,
				},
			})
		if err != nil {
			s.log.Errorf("error updating workloadsToHostPolicy %v", err)
			return
		}
	}
	if !protoPortListEqual(s.cache.FelixConfig.FailsafeInboundHostPorts, old.FailsafeInboundHostPorts) ||
		!protoPortListEqual(s.cache.FelixConfig.FailsafeOutboundHostPorts, old.FailsafeOutboundHostPorts) {
		err := s.createFailSafePolicies()
		if err != nil {
			s.log.Errorf("error updating FailSafePolicies %v", err)
			return
		}
	}
}

// Reconciles the pending state with the configured state
func (s *PoliciesHandler) applyPendingState() (err error) {
	s.log.Infof("Reconciliating pending policy state with configured state")
	// Stupid algorithm for now, delete all that is in configured state, and then recreate everything
	for _, wep := range s.configuredState.WorkloadEndpoints {
		if len(wep.SwIfIndex) != 0 {
			err = s.DeleteWorkloadEndpoint(wep)
			if err != nil {
				return errors.Wrap(err, "cannot cleanup workload endpoint")
			}
		}
	}
	for _, policy := range s.configuredState.Policies {
		err = policy.Delete(s.vpp, s.configuredState)
		if err != nil {
			s.log.Warnf("error deleting policy: %v", err)
		}
	}
	for _, profile := range s.configuredState.Profiles {
		err = profile.Delete(s.vpp, s.configuredState)
		if err != nil {
			s.log.Warnf("error deleting profile: %v", err)
		}
	}
	for _, ipset := range s.configuredState.IPSets {
		err = ipset.Delete(s.vpp)
		if err != nil {
			s.log.Warnf("error deleting ipset: %v", err)
		}
	}
	for _, hep := range s.configuredState.HostEndpoints {
		if len(hep.UplinkSwIfIndexes) != 0 {
			err = s.DeleteHostEndpoint(hep, s.configuredState)
			if err != nil {
				s.log.Warnf("error deleting hostendpoint : %v", err)
			}
		}
	}

	s.configuredState = s.pendingState
	s.pendingState = NewPolicyState()
	for _, ipset := range s.configuredState.IPSets {
		err = ipset.Create(s.vpp)
		if err != nil {
			return errors.Wrap(err, "error creating ipset")
		}
	}
	for _, profile := range s.configuredState.Profiles {
		err = profile.Create(s.vpp, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "error creating profile")
		}
	}
	for _, policy := range s.configuredState.Policies {
		err = policy.Create(s.vpp, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "error creating policy")
		}
	}
	for id, wep := range s.configuredState.WorkloadEndpoints {
		intf, intfFound := s.endpointsInterfaces[id]
		if intfFound {
			swIfIndexList := []uint32{}
			for _, idx := range intf {
				swIfIndexList = append(swIfIndexList, idx)
			}
			err = s.CreateWorkloadEndpoint(wep, swIfIndexList, s.configuredState, id.Network)
			if err != nil {
				return errors.Wrap(err, "cannot configure workload endpoint")
			}
		}
	}
	for _, hep := range s.configuredState.HostEndpoints {
		err = s.CreateHostEndpoint(hep, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "cannot create host endpoint")
		}
	}
	s.log.Infof("Reconciliation done")
	return nil
}

func (s *PoliciesHandler) createAllowToHostPolicy() (err error) {
	s.log.Infof("Creating policy to allow traffic to host that is applied on uplink")
	ruleIn := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowtohost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			DstNet: []net.IPNet{},
		},
	}
	ruleOut := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowtohost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			SrcNet: []net.IPNet{},
		},
	}
	if s.cache.GetNodeIP4() != nil {
		ruleIn.DstNet = append(ruleIn.DstNet, *common.FullyQualified(*s.cache.GetNodeIP4()))
		ruleOut.SrcNet = append(ruleOut.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP4()))
	}
	if s.cache.GetNodeIP6() != nil {
		ruleIn.DstNet = append(ruleIn.DstNet, *common.FullyQualified(*s.cache.GetNodeIP6()))
		ruleOut.SrcNet = append(ruleOut.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP6()))
	}

	allowToHostPolicy := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	allowToHostPolicy.InboundRules = append(allowToHostPolicy.InboundRules, ruleIn)
	allowToHostPolicy.OutboundRules = append(allowToHostPolicy.OutboundRules, ruleOut)
	if s.allowToHostPolicy == nil {
		err = allowToHostPolicy.Create(s.vpp, nil)
	} else {
		allowToHostPolicy.VppID = s.allowToHostPolicy.VppID
		err = s.allowToHostPolicy.Update(s.vpp, allowToHostPolicy, nil)
	}
	s.allowToHostPolicy = allowToHostPolicy
	if err != nil {
		return errors.Wrap(err, "cannot create policy to allow traffic to host")
	}
	s.log.Infof("Created policy to allow traffic to host with ID: %+v", s.allowToHostPolicy.VppID)
	return nil
}

func (s *PoliciesHandler) createAllPodsIpset() (err error) {
	ipset := NewIPSet()
	err = ipset.Create(s.vpp)
	if err != nil {
		return err
	}
	s.allPodsIpset = ipset
	return nil
}

func (s *PoliciesHandler) OnNodeAdded(node *common.LocalNodeSpec) {
	if node.Name == *config.NodeName &&
		(node.IPv4Address != nil || node.IPv6Address != nil) {
		err := s.createAllowFromHostPolicy()
		if err != nil {
			s.log.Errorf("Error in creating AllowFromHostPolicy %v", err)
			return
		}
		err = s.createAllowToHostPolicy()
		if err != nil {
			s.log.Errorf("Error in createAllowToHostPolicy %v", err)
			return
		}
	}
}

// createAllowFromHostPolicy creates a policy allowing host->pod communications. This is needed
// to maintain vanilla Calico's behavior where the host can always reach pods.
// This policy is applied in Egress on the host endpoint tap (i.e. linux -> VPP)
// and on the Ingress of Workload endpoints (i.e. VPP -> pod)
func (s *PoliciesHandler) createAllowFromHostPolicy() (err error) {
	s.log.Infof("Creating rules to allow traffic from host to pods with egress policies")
	ruleOut := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-egressallowfromhost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
		},
		DstIPSetNames: []string{"calico-vpp-wep-addr-ipset"},
	}
	ps := PolicyState{IPSets: map[string]*IPSet{"calico-vpp-wep-addr-ipset": s.allPodsIpset}}
	s.log.Infof("Creating rules to allow traffic from host to pods with ingress policies")
	ruleIn := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-ingressallowfromhost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			SrcNet: []net.IPNet{},
		},
	}
	if s.cache.GetNodeIP4() != nil {
		ruleIn.SrcNet = append(ruleIn.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP4()))
	}
	if s.cache.GetNodeIP6() != nil {
		ruleIn.SrcNet = append(ruleIn.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP6()))
	}

	allowFromHostPolicy := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	allowFromHostPolicy.OutboundRules = append(allowFromHostPolicy.OutboundRules, ruleOut)
	allowFromHostPolicy.InboundRules = append(allowFromHostPolicy.InboundRules, ruleIn)
	if s.AllowFromHostPolicy == nil {
		err = allowFromHostPolicy.Create(s.vpp, &ps)
	} else {
		allowFromHostPolicy.VppID = s.AllowFromHostPolicy.VppID
		err = s.AllowFromHostPolicy.Update(s.vpp, allowFromHostPolicy, &ps)
	}
	s.AllowFromHostPolicy = allowFromHostPolicy
	if err != nil {
		return errors.Wrap(err, "cannot create policy to allow traffic from host to pods")
	}
	s.log.Infof("Created allow from host to pods traffic with ID: %+v", s.AllowFromHostPolicy.VppID)
	return nil
}

func (s *PoliciesHandler) createEndpointToHostPolicy( /*may be return*/ ) (err error) {
	workloadsToHostPolicy := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	workloadsToHostRule := &Rule{
		VppID: types.InvalidID,
		Rule: &types.Rule{
			Action: s.getEndpointToHostAction(),
		},
		SrcIPSetNames: []string{"calico-vpp-wep-addr-ipset"},
	}
	ps := PolicyState{
		IPSets: map[string]*IPSet{
			"calico-vpp-wep-addr-ipset": s.allPodsIpset,
		},
	}
	workloadsToHostPolicy.InboundRules = append(workloadsToHostPolicy.InboundRules, workloadsToHostRule)

	err = workloadsToHostPolicy.Create(s.vpp, &ps)
	if err != nil {
		return err
	}
	s.workloadsToHostPolicy = workloadsToHostPolicy

	allowAllPol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
		InboundRules: []*Rule{
			{
				VppID: types.InvalidID,
				Rule: &types.Rule{
					Action: types.ActionAllow,
				},
			},
		},
	}
	err = allowAllPol.Create(s.vpp, &ps)
	if err != nil {
		return err
	}
	conf := types.NewInterfaceConfig()
	conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, s.workloadsToHostPolicy.VppID, allowAllPol.VppID)
	swifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("host-") // tap0 interfaces
	if err != nil {
		s.log.Error(err)
	}
	for _, swifindex := range swifindexes {
		err = s.vpp.ConfigurePolicies(uint32(swifindex), conf, 0)
		if err != nil {
			s.log.Error("cannot create policy to drop traffic to host")
		}
	}
	s.defaultTap0IngressConf = conf.IngressPolicyIDs
	return nil
}

// createFailSafePolicies ensures the failsafe policies defined in the Felixconfiguration exist in VPP.
// check https://github.com/projectcalico/calico/blob/master/felix/rules/static.go :: failsafeInChain for the linux implementation
// To be noted. This does not implement the doNotTrack case as we do not yet support doNotTrack
func (s *PoliciesHandler) createFailSafePolicies() (err error) {
	failSafePol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}

	if len(s.cache.FelixConfig.FailsafeInboundHostPorts) != 0 {
		for _, protoPort := range s.cache.FelixConfig.FailsafeInboundHostPorts {
			protocol, err := ParseProtocol(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: protoPort.Protocol}})
			if err != nil {
				s.log.WithError(err).Error("Failed to parse protocol in inbound failsafe rule. Skipping failsafe rule")
				continue
			}
			rule := &Rule{
				VppID:  types.InvalidID,
				RuleID: fmt.Sprintf("failsafe-in-%s-%s-%d", protoPort.Net, protoPort.Protocol, protoPort.Port),
				Rule: &types.Rule{
					Action: types.ActionAllow,
					// Ports are always filtered on the destination of packets
					DstPortRange: []types.PortRange{{First: protoPort.Port, Last: protoPort.Port}},
					Filters: []types.RuleFilter{{
						ShouldMatch: true,
						Type:        types.CapoFilterProto,
						Value:       int(protocol),
					}},
				},
			}
			if protoPort.Net != "" {
				_, protoPortNet, err := net.ParseCIDR(protoPort.Net)
				if err != nil {
					s.log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
					continue
				}
				// Inbound packets are checked for where they come FROM
				rule.SrcNet = append(rule.SrcNet, *protoPortNet)
			}
			failSafePol.InboundRules = append(failSafePol.InboundRules, rule)
		}
	}

	if len(s.cache.FelixConfig.FailsafeOutboundHostPorts) != 0 {
		for _, protoPort := range s.cache.FelixConfig.FailsafeOutboundHostPorts {
			protocol, err := ParseProtocol(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: protoPort.Protocol}})
			if err != nil {
				s.log.WithError(err).Error("Failed to parse protocol in outbound failsafe rule. Skipping failsafe rule")
				continue
			}
			rule := &Rule{
				VppID:  types.InvalidID,
				RuleID: fmt.Sprintf("failsafe-out-%s-%s-%d", protoPort.Net, protoPort.Protocol, protoPort.Port),
				Rule: &types.Rule{
					Action: types.ActionAllow,
					// Ports are always filtered on the destination of packets
					DstPortRange: []types.PortRange{{First: protoPort.Port, Last: protoPort.Port}},
					Filters: []types.RuleFilter{{
						ShouldMatch: true,
						Type:        types.CapoFilterProto,
						Value:       int(protocol),
					}},
				},
			}
			if protoPort.Net != "" {
				_, protoPortNet, err := net.ParseCIDR(protoPort.Net)
				if err != nil {
					s.log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
					continue
				}
				// Outbound packets are checked for where they go TO
				rule.DstNet = append(rule.DstNet, *protoPortNet)
			}
			failSafePol.OutboundRules = append(failSafePol.OutboundRules, rule)
		}
	}

	if s.failSafePolicy == nil {
		err = failSafePol.Create(s.vpp, nil)

	} else {
		failSafePol.VppID = s.failSafePolicy.VppID
		err = s.failSafePolicy.Update(s.vpp, failSafePol, nil)
	}
	if err != nil {
		return err
	}
	s.failSafePolicy = failSafePol
	s.log.Infof("Created failsafe policy with ID %+v", s.failSafePolicy.VppID)
	return nil
}

func (s *PoliciesHandler) getTapPolicies(h *HostEndpoint, state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf, err = h.GetHostPolicies(state, h.Tiers)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create host policies for TapConf")
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, s.workloadsToHostPolicy.VppID)
		conf.IngressPolicyIDs = append([]uint32{s.failSafePolicy.VppID}, conf.IngressPolicyIDs...)
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{s.AllowFromHostPolicy.VppID}, conf.EgressPolicyIDs...)
		conf.EgressPolicyIDs = append([]uint32{s.failSafePolicy.VppID}, conf.EgressPolicyIDs...)
	}
	return conf, nil
}

func (s *PoliciesHandler) getForwardPolicies(h *HostEndpoint, state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf, err = h.GetHostPolicies(state, h.ForwardTiers)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create host policies for forwardConf")
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{s.allowToHostPolicy.VppID}, conf.EgressPolicyIDs...)
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{s.allowToHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	return conf, nil
}

func (s *PoliciesHandler) CreateHostEndpoint(h *HostEndpoint, state *PolicyState) (err error) {
	forwardConf, err := s.getForwardPolicies(h, state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		s.log.Infof("policy(add) interface swif=%d conf=%v", swIfIndex, forwardConf)
		err = s.vpp.ConfigurePolicies(swIfIndex, forwardConf, 1 /*invertRxTx*/)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	h.CurrentForwardConf = forwardConf
	tapConf, err := s.getTapPolicies(h, state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		s.log.Infof("policy(add) interface swif=%d conf=%v", swIfIndex, tapConf)
		err = s.vpp.ConfigurePolicies(swIfIndex, tapConf, 0)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	return nil
}

func (s *PoliciesHandler) UpdateHostEndpoint(h *HostEndpoint, new *HostEndpoint, state *PolicyState) (err error) {
	forwardConf, err := s.getForwardPolicies(new, state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		s.log.Infof("policy(upd) interface swif=%d conf=%v", swIfIndex, forwardConf)
		err = s.vpp.ConfigurePolicies(swIfIndex, forwardConf, 1 /* invertRxTx */)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	h.CurrentForwardConf = forwardConf
	tapConf, err := s.getTapPolicies(new, state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		s.log.Infof("policy(upd) interface swif=%d conf=%v", swIfIndex, tapConf)
		err = s.vpp.ConfigurePolicies(swIfIndex, tapConf, 0)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	// Update local policy with new data
	h.Profiles = new.Profiles
	h.Tiers = new.Tiers
	h.ForwardTiers = new.ForwardTiers
	return nil
}

func (s *PoliciesHandler) DeleteHostEndpoint(h *HostEndpoint, state *PolicyState) (err error) {
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		// Unconfigure forward policies
		s.log.Infof("policy(del) interface swif=%d", swIfIndex)
		err = s.vpp.ConfigurePolicies(swIfIndex, types.NewInterfaceConfig(), 0)
		if err != nil {
			return errors.Wrapf(err, "cannot unconfigure policies on interface %d", swIfIndex)
		}
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		// Unconfigure tap0 policies
		s.log.Infof("policy(del) interface swif=%d", swIfIndex)
		conf := types.NewInterfaceConfig()
		conf.IngressPolicyIDs = s.defaultTap0IngressConf
		err = s.vpp.ConfigurePolicies(swIfIndex, conf, 0)
		if err != nil {
			return errors.Wrapf(err, "cannot unconfigure policies on interface %d", swIfIndex)
		}
	}
	h.UplinkSwIfIndexes = []uint32{}
	h.TapSwIfIndexes = []uint32{}
	h.TunnelSwIfIndexes = []uint32{}
	return nil
}

func (s *PoliciesHandler) getPolicies(w *WorkloadEndpoint, state *PolicyState, network string) (conf *types.InterfaceConfig, err error) {
	conf = types.NewInterfaceConfig()
	for _, tier := range w.Tiers {
		for _, polName := range tier.IngressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName, Network: network}]
			if !ok {
				return nil, fmt.Errorf("in policy %s tier %s not found for workload endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("in policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, pol.VppID)
		}
		for _, polName := range tier.EgressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName, Network: network}]
			if !ok {
				return nil, fmt.Errorf("out policy %s tier %s not found for workload endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("out policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			conf.EgressPolicyIDs = append(conf.EgressPolicyIDs, pol.VppID)
		}
	}
	for _, profileName := range w.Profiles {
		prof, ok := state.Profiles[profileName]
		if !ok {
			return nil, fmt.Errorf("profile %s not found for workload endpoint", profileName)
		}
		if prof.VppID == types.InvalidID {
			return nil, fmt.Errorf("profile %s not yet created in VPP", profileName)
		}
		conf.ProfileIDs = append(conf.ProfileIDs, prof.VppID)
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{s.AllowFromHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	return conf, nil
}

func (s *PoliciesHandler) CreateWorkloadEndpoint(w *WorkloadEndpoint, swIfIndexes []uint32, state *PolicyState, network string) (err error) {
	conf, err := s.getPolicies(w, state, network)
	if err != nil {
		return err
	}
	for _, swIfIndex := range swIfIndexes {
		err = s.vpp.ConfigurePolicies(swIfIndex, conf, 0)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}

	w.SwIfIndex = append(w.SwIfIndex, swIfIndexes...)
	return nil
}

func (s *PoliciesHandler) UpdateWorkloadEndpoint(w *WorkloadEndpoint, new *WorkloadEndpoint, state *PolicyState, network string) (err error) {
	conf, err := s.getPolicies(new, state, network)
	if err != nil {
		return err
	}
	for _, swIfIndex := range w.SwIfIndex {
		err = s.vpp.ConfigurePolicies(swIfIndex, conf, 0)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	// Update local policy with new data
	w.Profiles = new.Profiles
	w.Tiers = new.Tiers
	return nil
}

func (s *PoliciesHandler) DeleteWorkloadEndpoint(w *WorkloadEndpoint) (err error) {
	if len(w.SwIfIndex) == 0 {
		return fmt.Errorf("deleting unconfigured wep")
	}
	// Nothing to do in VPP, policies are cleared when the interface is removed
	w.SwIfIndex = []uint32{}
	return nil
}

func (s *PoliciesHandler) PoliciesHandlerInit() error {
	err := s.createAllPodsIpset()
	if err != nil {
		return errors.Wrap(err, "Error in createallPodsIpset")
	}
	err = s.createEndpointToHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createEndpointToHostPolicy")
	}
	err = s.createAllowFromHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in creating AllowFromHostPolicy")
	}
	err = s.createAllowToHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createAllowToHostPolicy")
	}
	err = s.createFailSafePolicies()
	if err != nil {
		return errors.Wrap(err, "Error in createFailSafePolicies")
	}
	s.interfacesMap, err = s.mapTagToInterfaceDetails()
	if err != nil {
		return errors.Wrap(err, "Error in mapping uplink to tap interfaces")
	}
	return nil
}

func (s *PoliciesHandler) getEndpointToHostAction() types.RuleAction {
	if strings.ToUpper(s.cache.FelixConfig.DefaultEndpointToHostAction) == "ACCEPT" {
		return types.ActionAllow
	}
	return types.ActionDeny
}

// workloadAdded is called by the CNI server when a container interface is created,
// either during startup when reconnecting the interfaces, or when a new pod is created
func (s *PoliciesHandler) OnWorkloadAdded(id *WorkloadEndpointID, swIfIndex uint32, ifName string, containerIPs []*net.IPNet) {
	// TODO: Send WorkloadEndpointStatusUpdate to felix

	intf, existing := s.endpointsInterfaces[*id]

	if existing {
		for _, exInt := range intf {
			if swIfIndex == exInt {
				return
			}
		}
		// VPP restarted and interfaces are being reconnected
		s.log.Warnf("workload endpoint changed interfaces, did VPP restart? %v %v -> %d", id, intf, swIfIndex)
		s.endpointsInterfaces[*id][ifName] = swIfIndex
	}

	s.log.Infof("policy(add) Workload id=%v swIfIndex=%d", id, swIfIndex)
	if s.endpointsInterfaces[*id] == nil {
		s.endpointsInterfaces[*id] = map[string]uint32{ifName: swIfIndex}
	} else {
		s.endpointsInterfaces[*id][ifName] = swIfIndex
	}

	if s.state == common.StateInSync {
		wep, ok := s.configuredState.WorkloadEndpoints[*id]
		if !ok {
			s.log.Infof("not creating wep in workloadadded")
			// Nothing to configure
		} else {
			s.log.Infof("creating wep in workloadadded")
			err := s.CreateWorkloadEndpoint(wep, []uint32{swIfIndex}, s.configuredState, id.Network)
			if err != nil {
				s.log.Errorf("Error processing workload addition: %s", err)
			}
		}
	}
	// EndpointToHostAction
	allMembers := []string{}
	for _, containerIP := range containerIPs {
		allMembers = append(allMembers, containerIP.IP.String())
	}
	err := s.allPodsIpset.AddMembers(allMembers, true, s.vpp)
	if err != nil {
		s.log.Errorf("Error processing workload addition: %s", err)
	}
}

// WorkloadRemoved is called by the CNI server when the interface of a pod is deleted
func (s *PoliciesHandler) OnWorkloadRemoved(id *WorkloadEndpointID, containerIPs []*net.IPNet) {
	// TODO: Send WorkloadEndpointStatusRemove to felix

	_, existing := s.endpointsInterfaces[*id]
	if !existing {
		s.log.Warnf("nonexistent workload endpoint removed %v", id)
		return
	}
	s.log.Infof("policy(del) workload id=%v", id)

	if s.state == common.StateInSync {
		wep, ok := s.configuredState.WorkloadEndpoints[*id]
		if !ok {
			// Nothing to clean up
		} else {
			err := s.DeleteWorkloadEndpoint(wep)
			if err != nil {
				s.log.Errorf("Error processing workload removal: %s", err)
			}
		}
	}
	delete(s.endpointsInterfaces, *id)
	// EndpointToHostAction
	allMembers := []string{}
	for _, containerIP := range containerIPs {
		allMembers = append(allMembers, containerIP.IP.String())
	}
	err := s.allPodsIpset.RemoveMembers(allMembers, true, s.vpp)
	if err != nil {
		s.log.Errorf("Error processing workload remove: %s", err)
	}
}

type interfaceDetails struct {
	tapIndex    uint32
	uplinkIndex uint32
	addresses   []string
}

func (s *PoliciesHandler) mapTagToInterfaceDetails() (tagIfDetails map[string]interfaceDetails, err error) {
	tagIfDetails = make(map[string]interfaceDetails)
	uplinkSwifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("main-")
	if err != nil {
		return nil, err
	}
	tapSwifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("host-")
	if err != nil {
		return nil, err
	}
	for intf, uplink := range uplinkSwifindexes {
		tap, found := tapSwifindexes["host-"+intf[5:]]
		if found {
			ip4adds, err := s.vpp.AddrList(uplink, false)
			if err != nil {
				return nil, err
			}
			ip6adds, err := s.vpp.AddrList(uplink, true)
			if err != nil {
				return nil, err
			}
			adds := append(ip4adds, ip6adds...)
			addresses := []string{}
			for _, add := range adds {
				addresses = append(addresses, add.IPNet.IP.String())
			}
			tagIfDetails[intf[5:]] = interfaceDetails{tap, uplink, addresses}
		} else {
			return nil, errors.Errorf("uplink interface %d not corresponding to a tap interface", uplink)
		}
	}
	return tagIfDetails, nil
}

func (s *PoliciesHandler) handleTunnelChange(h *HostEndpoint, swIfIndex uint32, isAdd bool, pending bool) (err error) {
	if isAdd {
		newTunnel := true
		for _, v := range h.TunnelSwIfIndexes {
			if v == swIfIndex {
				newTunnel = false
			}
		}
		if newTunnel {
			h.TunnelSwIfIndexes = append(h.TunnelSwIfIndexes, swIfIndex)
			s.log.Infof("Configuring policies on added tunnel [%d]", swIfIndex)
			if !pending {
				s.log.Infof("policy(upd) interface swif=%d", swIfIndex)
				err = s.vpp.ConfigurePolicies(swIfIndex, h.CurrentForwardConf, 1 /*invertRxTx*/)
				if err != nil {
					return errors.Wrapf(err, "cannot configure policies on tunnel interface %d", swIfIndex)
				}
			}
		}
	} else { // delete case
		for index, existingSwifindex := range h.TunnelSwIfIndexes {
			if existingSwifindex == swIfIndex {
				// we don't delete the policies because they are auto-deleted when interfaces are removed
				h.TunnelSwIfIndexes = append(h.TunnelSwIfIndexes[:index], h.TunnelSwIfIndexes[index+1:]...)
			}
		}
	}
	return err
}
