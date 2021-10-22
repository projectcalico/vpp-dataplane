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
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type HostEndpointID struct {
	EndpointID string
}

type HostEndpoint struct {
	SwIfIndex        uint32
	Profiles         []string
	Tiers            []Tier
	server           *Server
	InterfaceName    string
	FailSafepolicies []*Policy
	expectedIPs      []string
}

func (he *HostEndpoint) String() string {
	return fmt.Sprintf("if[%d] profiles:[%s] tiers:[%s]", he.SwIfIndex, he.Profiles, he.Tiers)
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
		SwIfIndex:        types.InvalidID,
		InterfaceName:    hep.Name,
		FailSafepolicies: []*Policy{},
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

func (h *HostEndpoint) getProtocolRules(protocolName string, failSafe string) (*Rule, error) {
	portRanges := []types.PortRange{}

	failSafe = strings.Join(strings.Fields(failSafe), "")
	protocolsPorts := strings.Split(failSafe, ",")
	for _, protocolPort := range protocolsPorts {
		protocolAndPort := strings.Split(protocolPort, ":")
		if len(protocolAndPort) != 2 {
			return nil, errors.Errorf("failsafe has wrong format")
		}
		protocol := protocolAndPort[0]
		port := protocolAndPort[1]
		if protocol == protocolName {
			port, err := strconv.Atoi(port)
			if err != nil {
				return nil, errors.Errorf("failsafe has wrong format")
			}
			portRanges = append(portRanges, types.PortRange{First: uint16(port), Last: uint16(port)})
		}
	}
	protocol, err := parseProtocol(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: protocolName}})
	if err != nil {
		return nil, err
	}
	r_failsafe := &Rule{
		VppID:  types.InvalidID,
		RuleID: "failsafe" + protocolName,
		Rule: &types.Rule{
			Action:       types.ActionAllow,
			DstPortRange: portRanges,
			Filters: []types.RuleFilter{{
				ShouldMatch: true,
				Type:        types.CapoFilterProto,
				Value:       int(protocol),
			}},
		},
	}
	return r_failsafe, nil
}

func (h *HostEndpoint) getfailSafeRules(failSafe string) ([]*Rule, error) {
	r_failsafe_tcp, err := h.getProtocolRules("tcp", failSafe)
	if err != nil {
		return nil, errors.Errorf("failsafe has wrong format")
	}
	r_failsafe_udp, err := h.getProtocolRules("udp", failSafe)
	if err != nil {
		return nil, errors.Errorf("failsafe has wrong format")
	}
	return []*Rule{r_failsafe_tcp, r_failsafe_udp}, nil
}

func (h *HostEndpoint) failSafeInboundOutbound(initialConf *types.InterfaceConfig, failSafeInbound string, failSafeOutbound string) (conf *types.InterfaceConfig, err error) {
	ingressPol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	egressPol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	failSafeInboundRules, err := h.getfailSafeRules(failSafeInbound)
	if err != nil {
		return initialConf, err
	}
	failSafeOutboundRules, err := h.getfailSafeRules(failSafeOutbound)
	if err != nil {
		return initialConf, err
	}
	ingressPol.InboundRules = append(failSafeInboundRules, ingressPol.InboundRules...)
	egressPol.OutboundRules = append(failSafeOutboundRules, egressPol.OutboundRules...)
	err = ingressPol.Create(h.server.vpp, nil)
	if err != nil {
		return conf, err
	}
	err = egressPol.Create(h.server.vpp, nil)
	if err != nil {
		return conf, err
	}
	initialConf.IngressPolicyIDs = append(initialConf.IngressPolicyIDs, ingressPol.VppID)
	initialConf.EgressPolicyIDs = append(initialConf.EgressPolicyIDs, egressPol.VppID)
	h.FailSafepolicies = append(h.FailSafepolicies, []*Policy{ingressPol, egressPol}...)
	conf = initialConf
	return conf, nil
}

func (h *HostEndpoint) Create(vpp *vpplink.VppLink, swIfIndex uint32, state *PolicyState, failSafeInbound string, failSafeOutbound string) (err error) {
	conf, err := h.getPolicies(state)
	if err != nil {
		return err
	}
	conf, err = h.failSafeInboundOutbound(conf, failSafeInbound, failSafeOutbound)
	if err != nil {
		return err
	}
	err = vpp.ConfigurePolicies(swIfIndex, conf)
	if err != nil {
		return errors.Wrapf(err, "cannot configure policies on interface %d", swIfIndex)
	}

	return nil
}

func (h *HostEndpoint) Update(vpp *vpplink.VppLink, new *HostEndpoint, state *PolicyState, failSafeInbound string, failSafeOutbound string) (err error) {
	conf, err := new.getPolicies(state)
	if err != nil {
		return err
	}
	conf, err = h.failSafeInboundOutbound(conf, failSafeInbound, failSafeOutbound)
	if err != nil {
		return err
	}
	err = vpp.ConfigurePolicies(h.SwIfIndex, conf)
	if err != nil {
		return errors.Wrapf(err, "cannot configure policies on interface %d", h.SwIfIndex)
	}

	// Update local policy with new data
	h.Profiles = new.Profiles
	h.Tiers = new.Tiers
	return nil
}

func (h *HostEndpoint) Delete(vpp *vpplink.VppLink) (err error) {
	if h.SwIfIndex == types.InvalidID {
		return fmt.Errorf("deleting unconfigured wep")
	}
	// Unconfigure policies
	err = vpp.ConfigurePolicies(h.SwIfIndex, types.NewInterfaceConfig())
	if err != nil {
		return errors.Wrapf(err, "cannot unconfigure policies on interface %d", h.SwIfIndex)
	}
	for _, failSafePol := range h.FailSafepolicies {
		failSafePol.Delete(vpp, nil)
	}
	h.SwIfIndex = types.InvalidID
	return nil
}
