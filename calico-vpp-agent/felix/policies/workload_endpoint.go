// Copyright (C) 2020 Cisco Systems Inc.
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

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/npol"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type WorkloadEndpointID struct {
	OrchestratorID string
	WorkloadID     string
	EndpointID     string
	Network        string
}

func (wi *WorkloadEndpointID) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", wi.OrchestratorID, wi.WorkloadID, wi.EndpointID, wi.Network)
}

type Tier struct {
	Name            string
	IngressPolicies []string
	EgressPolicies  []string
}

func (tr *Tier) String() string {
	s := fmt.Sprintf("name=%s", tr.Name)
	s += types.StrListToString(" IngressPolicies=", tr.IngressPolicies)
	s += types.StrListToString(" EgressPolicies=", tr.EgressPolicies)
	return s
}

type WorkloadEndpoint struct {
	SwIfIndex []uint32
	Profiles  []string
	Tiers     []Tier
}

func (w *WorkloadEndpoint) String() string {
	s := fmt.Sprintf("if=%d profiles=%s tiers=%s", w.SwIfIndex, w.Profiles, w.Tiers)
	s += types.StrListToString(" Profiles=", w.Profiles)
	s += types.StrableListToString(" Tiers=", w.Tiers)
	return s
}

func FromProtoEndpointID(ep *proto.WorkloadEndpointID) *WorkloadEndpointID {
	return &WorkloadEndpointID{
		OrchestratorID: ep.OrchestratorId,
		WorkloadID:     ep.WorkloadId,
		EndpointID:     ep.EndpointId,
	}
}

func FromProtoWorkload(wep *proto.WorkloadEndpoint) *WorkloadEndpoint {
	r := &WorkloadEndpoint{
		SwIfIndex: []uint32{},
		Profiles:  wep.ProfileIds,
	}
	for _, tier := range wep.Tiers {
		r.Tiers = append(r.Tiers, Tier{
			Name:            tier.Name,
			IngressPolicies: tier.IngressPolicies,
			EgressPolicies:  tier.EgressPolicies,
		})
	}
	return r
}

func (s *PoliciesHandler) getWepUserDefinedPolicies(w *WorkloadEndpoint, state *PolicyState, network string) (conf *types.InterfaceConfig, err error) {
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

// getWorkloadPolicies creates the interface configuration for a workload (pod) interface
// We have an implicit ingress policy that allows traffic coming from the host
// see createAllowFromHostPolicy()
// If there are no policies the default should be pass to profiles
// If there are policies the default should be deny (profiles are ignored)
func (s *PoliciesHandler) getWorkloadPolicies(w *WorkloadEndpoint, state *PolicyState, network string) (conf *types.InterfaceConfig, err error) {
	conf, err = s.getWepUserDefinedPolicies(w, state, network)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create workload policies")
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{s.AllowFromHostPolicy.VppID}, conf.IngressPolicyIDs...)
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
	} else if len(conf.ProfileIDs) > 0 {
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_PASS
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
	} else if len(conf.ProfileIDs) > 0 {
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_PASS
	}
	return conf, nil
}

func (s *PoliciesHandler) CreateWorkloadEndpoint(w *WorkloadEndpoint, swIfIndexes []uint32, state *PolicyState, network string) (err error) {
	conf, err := s.getWorkloadPolicies(w, state, network)
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

func (s *PoliciesHandler) updateWorkloadEndpoint(w *WorkloadEndpoint, new *WorkloadEndpoint, state *PolicyState, network string) (err error) {
	conf, err := s.getWorkloadPolicies(new, state, network)
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
				err := s.updateWorkloadEndpoint(existing, wep, state, id.Network)
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
