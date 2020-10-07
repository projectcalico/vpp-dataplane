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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

type WorkloadEndpointID struct {
	OrchestratorID string
	WorkloadID     string
	EndpointID     string
}

type Tier struct {
	Name            string
	IngressPolicies []string
	EgressPolicies  []string
}

type WorkloadEndpoint struct {
	SwIfIndex uint32
	Profiles  []string
	Tiers     []Tier
}

func fromProtoEndpointID(ep *proto.WorkloadEndpointID) *WorkloadEndpointID {
	return &WorkloadEndpointID{
		OrchestratorID: ep.OrchestratorId,
		WorkloadID:     ep.WorkloadId,
		EndpointID:     ep.EndpointId,
	}
}

func fromProtoWorkload(wep *proto.WorkloadEndpoint) *WorkloadEndpoint {
	r := &WorkloadEndpoint{
		SwIfIndex: types.InvalidID,
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

func (w *WorkloadEndpoint) getPolicies(state *PolicyState) (passId uint32, policies []uint32, err error) {
	policies = make([]uint32, 0)
	for _, tier := range w.Tiers {
		for _, polName := range append(tier.IngressPolicies, tier.EgressPolicies...) {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return 0, nil, fmt.Errorf("policy %s tier %s not found for workload endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return 0, nil, fmt.Errorf("policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			found := false
			for _, pID := range policies {
				if pID == pol.VppID {
					logrus.Warnf("duplicate policy specified %d", pID)
					found = true
				}
			}
			if !found {
				policies = append(policies, pol.VppID)
			}
		}
	}
	passID := uint32(len(policies))
	for _, profileName := range w.Profiles {
		prof, ok := state.Profiles[profileName]
		if !ok {
			return 0, nil, fmt.Errorf("profile %s not found for workload endpoint", profileName)
		}
		if prof.VppID == types.InvalidID {
			return 0, nil, fmt.Errorf("profile %s not yet created in VPP", profileName)
		}
		policies = append(policies, prof.VppID)
	}
	return passID, policies, nil
}

func (w *WorkloadEndpoint) Create(vpp *vpplink.VppLink, swIfIndex uint32, state *PolicyState) (err error) {
	passID, policies, err := w.getPolicies(state)
	if err != nil {
		return err
	}
	err = vpp.ConfigurePolicies(swIfIndex, passID, policies)
	if err != nil {
		return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
	}

	w.SwIfIndex = swIfIndex
	return nil
}

func (w *WorkloadEndpoint) Update(vpp *vpplink.VppLink, new *WorkloadEndpoint, state *PolicyState) (err error) {
	passID, policies, err := new.getPolicies(state)
	if err != nil {
		return err
	}
	err = vpp.ConfigurePolicies(w.SwIfIndex, passID, policies)
	if err != nil {
		return errors.Wrapf(err, "cannot configure policies on interface %d", w.SwIfIndex)
	}

	// Update local policy with new data
	w.Profiles = new.Profiles
	w.Tiers = new.Tiers
	return nil
}

func (w *WorkloadEndpoint) Delete(vpp *vpplink.VppLink) (err error) {
	if w.SwIfIndex == types.InvalidID {
		return fmt.Errorf("deleting unconfigured wep")
	}
	err = vpp.ConfigurePolicies(w.SwIfIndex, 0, nil)
	if err != nil {
		return errors.Wrapf(err, "cannot configure policies on interface %d", w.SwIfIndex)
	}
	w.SwIfIndex = types.InvalidID
	return nil
}
