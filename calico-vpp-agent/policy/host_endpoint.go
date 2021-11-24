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
	UplinkSwIfIndexes []uint32
	TapSwIfIndexes    []uint32
	TunnelSwIfIndexes []uint32
	Profiles          []string
	Tiers             []Tier
	ForwardTiers      []Tier
	server            *Server
	InterfaceName     string
	expectedIPs       []string

	currentForwardConf *types.InterfaceConfig
}

func (he *HostEndpoint) String() string {
	return fmt.Sprintf("%s: %+v : uplink[%d] tap[%d] tunnel [%d] profiles:[%s] tiers:[%s] forwardTiers [%s]",
		he.InterfaceName, he.expectedIPs, he.UplinkSwIfIndexes, he.TapSwIfIndexes, he.TunnelSwIfIndexes, he.Profiles, he.Tiers, he.ForwardTiers)
}

func fromProtoHostEndpointID(ep *proto.HostEndpointID) *HostEndpointID {
	return &HostEndpointID{
		EndpointID: ep.EndpointId,
	}
}

func fromProtoHostEndpoint(hep *proto.HostEndpoint, server *Server) *HostEndpoint {
	r := &HostEndpoint{
		Profiles:          hep.ProfileIds,
		server:            server,
		UplinkSwIfIndexes: []uint32{},
		TapSwIfIndexes:    []uint32{},
		TunnelSwIfIndexes: []uint32{},
		InterfaceName:     hep.Name,
		Tiers:             make([]Tier, 0),
		ForwardTiers:      make([]Tier, 0),
		expectedIPs:       append(hep.ExpectedIpv4Addrs, hep.ExpectedIpv6Addrs...),
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
			server.log.Error("Existing PreDnatTiers, not implemented")
		}
	}
	for _, tier := range hep.UntrackedTiers {
		if tier != nil {
			server.log.Error("Existing UntrackedTiers, not implemented")
		}
	}
	return r
}

func (h *HostEndpoint) getTapPolicies(state *PolicyState) (conf *types.InterfaceConfig, err error) {
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
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{h.server.workloadsToHostPolicy.VppID}, conf.IngressPolicyIDs...)
		conf.IngressPolicyIDs = append([]uint32{h.server.failSafePolicy.VppID}, conf.IngressPolicyIDs...)
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{h.server.failSafePolicy.VppID}, conf.EgressPolicyIDs...)
	}
	return conf, nil
}

func (h *HostEndpoint) getForwardPolicies(state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf = types.NewInterfaceConfig()
	for _, tier := range h.ForwardTiers {
		for _, polName := range tier.IngressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, fmt.Errorf("in policy %s tier %s not found for host endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("in policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			// reverse policy inbound and outbound rules
			newPol := &Policy{
				Policy: &types.Policy{},
				VppID:  types.InvalidID,
			}
			newPol.InboundRules = pol.OutboundRules
			newPol.OutboundRules = pol.InboundRules
			err := newPol.Create(h.server.vpp, state)
			if err != nil {
				return nil, err
			}
			conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, newPol.VppID)
		}
		for _, polName := range tier.EgressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, fmt.Errorf("out policy %s tier %s not found for host endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, fmt.Errorf("out policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			// reverse policy inbound and outbound rules
			newPol := &Policy{
				Policy: &types.Policy{},
				VppID:  types.InvalidID,
			}
			newPol.InboundRules = pol.OutboundRules
			newPol.OutboundRules = pol.InboundRules
			err := newPol.Create(h.server.vpp, state)
			if err != nil {
				return nil, err
			}
			conf.EgressPolicyIDs = append(conf.EgressPolicyIDs, newPol.VppID)
		}
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{h.server.allowToHostPolicy.VppID}, conf.EgressPolicyIDs...)
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{h.server.allowToHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	return conf, nil
}

func (h *HostEndpoint) Create(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	forwardConf, err := h.getForwardPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		err = vpp.ConfigurePolicies(swIfIndex, forwardConf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	h.currentForwardConf = forwardConf
	tapConf, err := h.getTapPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		err = vpp.ConfigurePolicies(swIfIndex, tapConf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	return nil
}

func (h *HostEndpoint) Update(vpp *vpplink.VppLink, new *HostEndpoint, state *PolicyState) (err error) {
	forwardConf, err := new.getForwardPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		err = vpp.ConfigurePolicies(swIfIndex, forwardConf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	h.currentForwardConf = forwardConf
	tapConf, err := new.getTapPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		err = vpp.ConfigurePolicies(swIfIndex, tapConf)
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

func (h *HostEndpoint) Delete(vpp *vpplink.VppLink) (err error) {
	for _, swIfIndex := range append(append(h.UplinkSwIfIndexes, h.TapSwIfIndexes...), h.TunnelSwIfIndexes...) {
		// Unconfigure policies
		err = vpp.ConfigurePolicies(swIfIndex, types.NewInterfaceConfig())
		if err != nil {
			return errors.Wrapf(err, "cannot unconfigure policies on interface %d", swIfIndex)
		}
	}
	h.UplinkSwIfIndexes = []uint32{}
	h.TapSwIfIndexes = []uint32{}
	h.TunnelSwIfIndexes = []uint32{}
	return nil
}
