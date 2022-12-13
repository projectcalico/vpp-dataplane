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
	server            *Server
	InterfaceName     string
	expectedIPs       []string

	currentForwardConf *types.InterfaceConfig
	ownPolicies        []Policy
}

func (he *HostEndpoint) String() string {
	s := fmt.Sprintf("ifName=%s", he.InterfaceName)
	s += types.StrListToString(" expectedIPs=", he.expectedIPs)
	s += types.IntListToString(" uplink=", he.UplinkSwIfIndexes)
	s += types.IntListToString(" tap=", he.TapSwIfIndexes)
	s += types.IntListToString(" uplink=", he.UplinkSwIfIndexes)
	s += types.IntListToString(" tunnel=", he.TunnelSwIfIndexes)
	s += types.StrListToString(" profiles=", he.Profiles)
	s += types.StrableListToString(" tiers=", he.Tiers)
	s += types.StrableListToString(" forwardTiers=", he.ForwardTiers)
	return s
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
		ownPolicies:       make([]Policy, 0),
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

func (h *HostEndpoint) handleTunnelChange(swIfIndex uint32, isAdd bool, pending bool) (err error) {
	if isAdd {
		newTunnel := true
		for _, v := range h.TunnelSwIfIndexes {
			if v == swIfIndex {
				newTunnel = false
			}
		}
		if newTunnel {
			h.TunnelSwIfIndexes = append(h.TunnelSwIfIndexes, swIfIndex)
			h.server.log.Infof("Configuring policies on added tunnel [%d]", swIfIndex)
			if !pending {
				h.server.log.Infof("policy(upd) interface swif=%d", swIfIndex)
				err = h.server.vpp.ConfigurePolicies(swIfIndex, h.currentForwardConf)
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

func (h *HostEndpoint) getForwardPolicies(state *PolicyState) (conf *types.InterfaceConfig, ownPolicies []Policy, err error) {
	conf = types.NewInterfaceConfig()
	ownPolicies = make([]Policy, 0)
	for _, tier := range h.ForwardTiers {
		for _, polName := range tier.IngressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, nil, fmt.Errorf("in policy %s tier %s not found for host endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, nil, fmt.Errorf("in policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			// reverse policy inbound and outbound rules
			newPol := &Policy{
				Policy: &types.Policy{},
				VppID:  types.InvalidID,
			}
			newPol.InboundRules = make([]*Rule, 0)
			for _, r := range pol.OutboundRules {
				newPol.InboundRules = append(newPol.InboundRules, r.DeepCopy())
			}
			newPol.OutboundRules = make([]*Rule, 0)
			for _, r := range pol.InboundRules {
				newPol.OutboundRules = append(newPol.OutboundRules, r.DeepCopy())
			}
			err := newPol.Create(h.server.vpp, state)
			if err != nil {
				return nil, nil, err
			}
			h.server.log.Infof("Created policy vpp-id=%d for forwardConf (ingress)", newPol.VppID)
			conf.EgressPolicyIDs = append(conf.EgressPolicyIDs, newPol.VppID)
			ownPolicies = append(ownPolicies, *newPol)
		}
		for _, polName := range tier.EgressPolicies {
			pol, ok := state.Policies[PolicyID{Tier: tier.Name, Name: polName}]
			if !ok {
				return nil, nil, fmt.Errorf("out policy %s tier %s not found for host endpoint", polName, tier.Name)
			}
			if pol.VppID == types.InvalidID {
				return nil, nil, fmt.Errorf("out policy %s tier %s not yet created in VPP", polName, tier.Name)
			}
			// reverse policy inbound and outbound rules
			newPol := &Policy{
				Policy: &types.Policy{},
				VppID:  types.InvalidID,
			}
			newPol.InboundRules = make([]*Rule, 0)
			for _, r := range pol.OutboundRules {
				newPol.InboundRules = append(newPol.InboundRules, r.DeepCopy())
			}
			newPol.OutboundRules = make([]*Rule, 0)
			for _, r := range pol.InboundRules {
				newPol.OutboundRules = append(newPol.OutboundRules, r.DeepCopy())
			}
			err = newPol.Create(h.server.vpp, state)
			if err != nil {
				return nil, nil, err
			}
			h.server.log.Infof("Created policy vpp-id=%d for forwardConf (egress)", newPol.VppID)
			conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, newPol.VppID)
			ownPolicies = append(ownPolicies, *newPol)
		}
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{h.server.allowToHostPolicy.VppID}, conf.EgressPolicyIDs...)
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{h.server.allowToHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	return conf, ownPolicies, nil
}

func (h *HostEndpoint) Create(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	forwardConf, ownPolicies, err := h.getForwardPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		h.server.log.Infof("policy(add) interface swif=%d conf=%v", swIfIndex, forwardConf)
		err = vpp.ConfigurePolicies(swIfIndex, forwardConf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	h.currentForwardConf = forwardConf
	h.ownPolicies = ownPolicies
	tapConf, err := h.getTapPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		h.server.log.Infof("policy(add) interface swif=%d conf=%v", swIfIndex, tapConf)
		err = vpp.ConfigurePolicies(swIfIndex, tapConf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	return nil
}

func (h *HostEndpoint) Update(vpp *vpplink.VppLink, new *HostEndpoint, state *PolicyState) (err error) {
	for _, policy := range h.ownPolicies {
		h.server.log.Infof("policy(upd) Deleting hep policy vpp-id=%d", policy.VppID)
		err = policy.Delete(vpp, state)
		if err != nil {
			h.server.log.Errorf("cannot delete policies for hep=%s %v", h, err)
		}
	}

	forwardConf, ownPolicies, err := new.getForwardPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		h.server.log.Infof("policy(upd) interface swif=%d conf=%v", swIfIndex, forwardConf)
		err = vpp.ConfigurePolicies(swIfIndex, forwardConf)
		if err != nil {
			return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
		}
	}
	h.currentForwardConf = forwardConf
	h.ownPolicies = ownPolicies
	tapConf, err := new.getTapPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		h.server.log.Infof("policy(upd) interface swif=%d conf=%v", swIfIndex, tapConf)
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

func (h *HostEndpoint) Delete(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	for _, policy := range h.ownPolicies {
		h.server.log.Infof("policy(del) Deleting hep policy vpp-id=%d", policy.VppID)
		err = policy.Delete(vpp, state)
		if err != nil {
			h.server.log.Errorf("cannot delete policies for hep=%s %v", h, err)
		}
	}

	for _, swIfIndex := range append(append(h.UplinkSwIfIndexes, h.TapSwIfIndexes...), h.TunnelSwIfIndexes...) {
		// Unconfigure policies
		h.server.log.Infof("policy(del) interface swif=%d", swIfIndex)
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
