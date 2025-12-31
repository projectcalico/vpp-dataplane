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

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/npol"
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

func (h *HostEndpoint) getUserDefinedPolicies(state *PolicyState, tiers []Tier) (conf *types.InterfaceConfig, err error) {
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

// This function creates the interface configuration for the host, applied on the vpptap0
// interface i.e. the tap interface from VPP to the host
// that we use as controlpoint for HostEndpoint implementation
// We have an implicit workloadsToHostPolicy policy that controls the traffic from
// workloads to their host: it is defined by felixConfig.DefaultEndpointToHostAction
// We have an implicit failsafe rules policy defined by felixConfig as well.
//
// If there are no policies the default should be pass to profiles
// If there are policies the default should be deny (profiles are ignored)
func (s *PoliciesHandler) getTapPolicies(h *HostEndpoint, state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf, err = h.getUserDefinedPolicies(state, h.Tiers)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create host policies for TapConf")
	}
	if len(conf.IngressPolicyIDs) == 0 && len(conf.ProfileIDs) == 0 {
		// If a host endpoint is created and network policy is not in place,
		// the Calico default is to deny traffic to/from that endpoint
		// (except for traffic allowed by failsafe rules).
		// note: this applies to ingress and egress separately, so if you don't have
		// ingress only you drop ingress
		conf.IngressPolicyIDs = []uint32{s.workloadsToHostPolicy.VppID, s.failSafePolicy.VppID}
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
	} else {
		if len(conf.IngressPolicyIDs) > 0 {
			conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
		} else if len(conf.ProfileIDs) > 0 {
			conf.PolicyDefaultTx = npol.NPOL_DEFAULT_PASS
		}
		conf.IngressPolicyIDs = append([]uint32{s.failSafePolicy.VppID}, conf.IngressPolicyIDs...)
		conf.IngressPolicyIDs = append([]uint32{s.workloadsToHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	if len(conf.EgressPolicyIDs) == 0 && len(conf.ProfileIDs) == 0 {
		conf.EgressPolicyIDs = []uint32{s.AllowFromHostPolicy.VppID, s.failSafePolicy.VppID}
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
	} else {
		if len(conf.EgressPolicyIDs) > 0 {
			conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
		} else if len(conf.ProfileIDs) > 0 {
			conf.PolicyDefaultRx = npol.NPOL_DEFAULT_PASS
		}
		conf.EgressPolicyIDs = append([]uint32{s.failSafePolicy.VppID}, conf.EgressPolicyIDs...)
		conf.EgressPolicyIDs = append([]uint32{s.AllowFromHostPolicy.VppID}, conf.EgressPolicyIDs...)
	}
	return conf, nil
}

func (s *PoliciesHandler) getForwardPolicies(h *HostEndpoint, state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf, err = h.getUserDefinedPolicies(state, h.ForwardTiers)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create host policies for forwardConf")
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{s.allowToHostPolicy.VppID}, conf.EgressPolicyIDs...)
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
	} else if len(conf.ProfileIDs) > 0 {
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_PASS
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{s.allowToHostPolicy.VppID}, conf.IngressPolicyIDs...)
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
	} else if len(conf.ProfileIDs) > 0 {
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_PASS
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
		conf.EgressPolicyIDs = s.defaultTap0EgressConf
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
