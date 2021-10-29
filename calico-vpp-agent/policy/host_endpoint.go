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

type HostEndpointID struct {
	EndpointID string
}

type HostEndpoint struct {
	SwIfIndexes      []uint32
	Profiles         []string
	Tiers            []Tier
	server           *Server
	InterfaceName    string
	expectedIPs      []string
}

func (he *HostEndpoint) String() string {
	return fmt.Sprintf("if[%d] profiles:[%s] tiers:[%s]", he.SwIfIndexes, he.Profiles, he.Tiers)
}

func fromProtoHostEndpointID(ep *proto.HostEndpointID) *HostEndpointID {
	return &HostEndpointID{
		EndpointID: ep.EndpointId,
	}
}

func fromProtoHostEndpoint(hep *proto.HostEndpoint, server *Server) *HostEndpoint {
	r := &HostEndpoint{
		Profiles:         hep.ProfileIds,
		server:           server,
		SwIfIndexes:      []uint32{},
		InterfaceName:    hep.Name,
		expectedIPs:      append(hep.ExpectedIpv4Addrs, hep.ExpectedIpv6Addrs...),
	}
	for _, tier := range hep.Tiers {
		r.Tiers = append(r.Tiers, Tier{
			Name:            tier.Name,
			IngressPolicies: tier.IngressPolicies,
			EgressPolicies:  tier.EgressPolicies,
		})
	}
	return r
}

func (h *HostEndpoint) getPolicies(state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf = types.NewInterfaceConfig()
	for _, tier := range h.Tiers {
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

func (h *HostEndpoint) Create(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	conf, err := h.getPolicies(state)
	if err != nil {
		return err
	}
	conf.IngressPolicyIDs = append([]uint32{h.server.ingressFailSafePolicy.VppID}, conf.IngressPolicyIDs...)
	conf.EgressPolicyIDs = append([]uint32{h.server.egressFailSafePolicy.VppID}, conf.EgressPolicyIDs...)
	for _, swIfIndex := range h.SwIfIndexes {
		err = vpp.ConfigurePolicies(swIfIndex, conf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}

	return nil
}

func (h *HostEndpoint) Update(vpp *vpplink.VppLink, new *HostEndpoint, state *PolicyState) (err error) {
	conf, err := new.getPolicies(state)
	if err != nil {
		return err
	}
	conf.IngressPolicyIDs = append([]uint32{h.server.ingressFailSafePolicy.VppID}, conf.IngressPolicyIDs...)
	conf.EgressPolicyIDs = append([]uint32{h.server.egressFailSafePolicy.VppID}, conf.EgressPolicyIDs...)
	for _, swIfIndex := range h.SwIfIndexes {
		err = vpp.ConfigurePolicies(swIfIndex, conf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	// Update local policy with new data
	h.Profiles = new.Profiles
	h.Tiers = new.Tiers
	return nil
}

func (h *HostEndpoint) Delete(vpp *vpplink.VppLink) (err error) {
	for _, swIfIndex := range h.SwIfIndexes {
		// Unconfigure policies
		err = vpp.ConfigurePolicies(swIfIndex, types.NewInterfaceConfig())
		if err != nil {
			return errors.Wrapf(err, "cannot unconfigure policies on interface %d", swIfIndex)
		}
	}
	h.SwIfIndexes = []uint32{}
	return nil
}
