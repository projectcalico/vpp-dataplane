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
	"fmt"

	"github.com/projectcalico/calico/felix/proto"

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
