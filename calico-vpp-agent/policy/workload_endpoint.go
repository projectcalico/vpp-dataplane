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

package policy

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	server    *Server
}

func (we *WorkloadEndpoint) String() string {
	s := fmt.Sprintf("if=%d profiles=%s tiers=%s", we.SwIfIndex, we.Profiles, we.Tiers)
	s += types.StrListToString(" Profiles=", we.Profiles)
	s += types.StrableListToString(" Tiers=", we.Tiers)
	return s
}

func fromProtoEndpointID(ep *proto.WorkloadEndpointID) *WorkloadEndpointID {
	return &WorkloadEndpointID{
		OrchestratorID: ep.OrchestratorId,
		WorkloadID:     ep.WorkloadId,
		EndpointID:     ep.EndpointId,
	}
}

func fromProtoWorkload(wep *proto.WorkloadEndpoint, server *Server) *WorkloadEndpoint {
	r := &WorkloadEndpoint{
		SwIfIndex: []uint32{},
		Profiles:  wep.ProfileIds,
		server:    server,
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

func (w *WorkloadEndpoint) getPolicies(state *PolicyState, network string) (conf *types.InterfaceConfig, err error) {
	conf = types.NewInterfaceConfig()
	for _, tier := range w.Tiers {
		var policyMap map[PolicyID]*Policy
		if network == "" {
			policyMap = state.Policies
		} else {
			policyMap = state.multinetPolicies[network]
		}
		for _, polName := range tier.IngressPolicies {
			pol, ok := policyMap[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, fmt.Errorf("in policy %s tier %s not found for workload endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("in policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, pol.VppID)
		}
		for _, polName := range tier.EgressPolicies {
			pol, ok := policyMap[PolicyID{Tier: tier.Name, Name: polName}]
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
		conf.IngressPolicyIDs = append([]uint32{w.server.allowFromHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	return conf, nil
}

func (w *WorkloadEndpoint) Create(vpp *vpplink.VppLink, swIfIndexes []uint32, state *PolicyState, network string) (err error) {
	conf, err := w.getPolicies(state, network)
	if err != nil {
		return err
	}
	for _, swIfIndex := range swIfIndexes {
		err = vpp.ConfigurePolicies(swIfIndex, conf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}

	w.SwIfIndex = append(w.SwIfIndex, swIfIndexes...)
	return nil
}

func (w *WorkloadEndpoint) Update(vpp *vpplink.VppLink, new *WorkloadEndpoint, state *PolicyState, network string) (err error) {
	conf, err := new.getPolicies(state, network)
	if err != nil {
		return err
	}
	for _, swIfIndex := range w.SwIfIndex {
		err = vpp.ConfigurePolicies(swIfIndex, conf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	// Update local policy with new data
	w.Profiles = new.Profiles
	w.Tiers = new.Tiers
	return nil
}

func (w *WorkloadEndpoint) Delete(vpp *vpplink.VppLink) (err error) {
	if len(w.SwIfIndex) == 0 {
		return fmt.Errorf("deleting unconfigured wep")
	}
	// Nothing to do in VPP, policies are cleared when the interface is removed
	w.SwIfIndex = []uint32{}
	return nil
}
