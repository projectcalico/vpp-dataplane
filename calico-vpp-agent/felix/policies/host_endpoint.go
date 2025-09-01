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

type HostEndpointID struct {
	EndpointID string
}

func (eid HostEndpointID) String() string {
	return eid.EndpointID
}

type HostEndpoint struct {
	UplinkSwIfIndexes []uint32
	TapSwIfIndexes    []uint32
	TunnelSwIfIndexes []uint32
	Profiles          []string
	Tiers             []Tier
	ForwardTiers      []Tier
	InterfaceName     string
	ExpectedIPs       []string

	CurrentForwardConf *types.InterfaceConfig
}

func (h *HostEndpoint) String() string {
	s := fmt.Sprintf("ifName=%s", h.InterfaceName)
	s += types.StrListToString(" ExpectedIPs=", h.ExpectedIPs)
	s += types.IntListToString(" uplink=", h.UplinkSwIfIndexes)
	s += types.IntListToString(" tap=", h.TapSwIfIndexes)
	s += types.IntListToString(" tunnel=", h.TunnelSwIfIndexes)
	s += types.StrListToString(" profiles=", h.Profiles)
	s += types.StrableListToString(" tiers=", h.Tiers)
	s += types.StrableListToString(" forwardTiers=", h.ForwardTiers)
	return s
}

func FromProtoHostEndpointID(ep *proto.HostEndpointID) *HostEndpointID {
	return &HostEndpointID{
		EndpointID: ep.EndpointId,
	}
}

func FromProtoHostEndpoint(hep *proto.HostEndpoint) (*HostEndpoint, error) {
	r := &HostEndpoint{
		Profiles:          hep.ProfileIds,
		UplinkSwIfIndexes: []uint32{},
		TapSwIfIndexes:    []uint32{},
		TunnelSwIfIndexes: []uint32{},
		InterfaceName:     hep.Name,
		Tiers:             make([]Tier, 0),
		ForwardTiers:      make([]Tier, 0),
		ExpectedIPs:       append(hep.ExpectedIpv4Addrs, hep.ExpectedIpv6Addrs...),
	}
	for _, tier := range hep.Tiers {
		r.Tiers = append(r.Tiers, Tier{
			Name:            tier.Name,
			IngressPolicies: tier.IngressPolicies,
			EgressPolicies:  tier.EgressPolicies,
		})
	}
	for _, tier := range hep.ForwardTiers {
		r.ForwardTiers = append(r.ForwardTiers, Tier{
			Name:            tier.Name,
			IngressPolicies: tier.IngressPolicies,
			EgressPolicies:  tier.EgressPolicies,
		})
	}
	for _, tier := range hep.PreDnatTiers {
		if tier != nil {
			return nil, fmt.Errorf("existing PreDnatTiers, not implemented")
		}
	}
	for _, tier := range hep.UntrackedTiers {
		if tier != nil {
			return nil, fmt.Errorf("existing UntrackedTiers, not implemented")
		}
	}
	return r, nil
}

func (h *HostEndpoint) GetHostPolicies(state *PolicyState, tiers []Tier) (conf *types.InterfaceConfig, err error) {
	conf = types.NewInterfaceConfig()
	for _, tier := range tiers {
		for _, polName := range tier.IngressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, fmt.Errorf("in policy %s tier %s not found for host endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("in policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, pol.VppID)
		}
		for _, polName := range tier.EgressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, fmt.Errorf("out policy %s tier %s not found for host endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("out policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			conf.EgressPolicyIDs = append(conf.EgressPolicyIDs, pol.VppID)
		}
	}
	for _, profileName := range h.Profiles {
		prof, ok := state.Profiles[profileName]
		if !ok {
			return nil, fmt.Errorf("profile %s not found for host endpoint", profileName)
		}
		if prof.VppID == types.InvalidID {
			return nil, fmt.Errorf("profile %s not yet created in VPP", profileName)
		}
		conf.ProfileIDs = append(conf.ProfileIDs, prof.VppID)
	}
	return conf, nil
}
