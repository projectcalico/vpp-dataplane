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

package felix

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
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
	server            *Server
	InterfaceName     string
	expectedIPs       []string

	currentForwardConf *types.InterfaceConfig
}

func (h *HostEndpoint) String() string {
	s := fmt.Sprintf("ifName=%s", h.InterfaceName)
	s += types.StrListToString(" expectedIPs=", h.expectedIPs)
	s += types.IntListToString(" uplink=", h.UplinkSwIfIndexes)
	s += types.IntListToString(" tap=", h.TapSwIfIndexes)
	s += types.IntListToString(" tunnel=", h.TunnelSwIfIndexes)
	s += types.StrListToString(" profiles=", h.Profiles)
	s += types.StrableListToString(" tiers=", h.Tiers)
	s += types.StrableListToString(" forwardTiers=", h.ForwardTiers)
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
				err = h.server.vpp.ConfigurePolicies(swIfIndex, h.currentForwardConf, 1 /*invertRxTx*/)
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

/*
	 This function creates the interface configuration for the host, applied on the vpptap0
		interface i.e. the tap interface from VPP to the host
		that we use as controlpoint for HostEndpoint implementation
		We have an implicit workloadsToHostPolicy policy that controls the traffic from
		workloads to their host: it is defined by felixConfig.DefaultEndpointToHostAction
		We have an implicit failsafe rules policy defined by felixConfig as well.

		If there are no policies the default should be pass to profiles
		If there are policies the default should be deny (profiles are ignored)
*/
func (h *HostEndpoint) getTapPolicies(state *PolicyState) (conf *types.InterfaceConfig, err error) {
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
		conf.IngressPolicyIDs = []uint32{h.server.workloadsToHostPolicy.VppID, h.server.failSafePolicy.VppID}
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
	} else {
		if len(conf.IngressPolicyIDs) > 0 {
			conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
		} else if len(conf.ProfileIDs) > 0 {
			conf.PolicyDefaultTx = npol.NPOL_DEFAULT_PASS
		}
		conf.IngressPolicyIDs = append([]uint32{h.server.failSafePolicy.VppID}, conf.IngressPolicyIDs...)
		conf.IngressPolicyIDs = append([]uint32{h.server.workloadsToHostPolicy.VppID}, conf.IngressPolicyIDs...)
	}
	if len(conf.EgressPolicyIDs) == 0 && len(conf.ProfileIDs) == 0 {
		conf.EgressPolicyIDs = []uint32{h.server.AllowFromHostPolicy.VppID, h.server.failSafePolicy.VppID}
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
	} else {
		if len(conf.EgressPolicyIDs) > 0 {
			conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
		} else if len(conf.ProfileIDs) > 0 {
			conf.PolicyDefaultRx = npol.NPOL_DEFAULT_PASS
		}
		conf.EgressPolicyIDs = append([]uint32{h.server.failSafePolicy.VppID}, conf.EgressPolicyIDs...)
		conf.EgressPolicyIDs = append([]uint32{h.server.AllowFromHostPolicy.VppID}, conf.EgressPolicyIDs...)
	}
	return conf, nil
}

func (h *HostEndpoint) getForwardPolicies(state *PolicyState) (conf *types.InterfaceConfig, err error) {
	conf, err = h.getUserDefinedPolicies(state, h.ForwardTiers)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create host policies for forwardConf")
	}
	if len(conf.EgressPolicyIDs) > 0 {
		conf.EgressPolicyIDs = append([]uint32{h.server.allowToHostPolicy.VppID}, conf.EgressPolicyIDs...)
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_DENY
	} else if len(conf.ProfileIDs) > 0 {
		conf.PolicyDefaultRx = npol.NPOL_DEFAULT_PASS
	}
	if len(conf.IngressPolicyIDs) > 0 {
		conf.IngressPolicyIDs = append([]uint32{h.server.allowToHostPolicy.VppID}, conf.IngressPolicyIDs...)
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_DENY
	} else if len(conf.ProfileIDs) > 0 {
		conf.PolicyDefaultTx = npol.NPOL_DEFAULT_PASS
	}
	return conf, nil
}

func (h *HostEndpoint) Create(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	forwardConf, err := h.getForwardPolicies(state)
	if err != nil {
		return err
	}
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		h.server.log.Infof("policy(add) interface swif=%d conf=%v", swIfIndex, forwardConf)
		err = vpp.ConfigurePolicies(swIfIndex, forwardConf, 1 /*invertRxTx*/)
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
		h.server.log.Infof("policy(add) interface swif=%d conf=%v", swIfIndex, tapConf)
		err = vpp.ConfigurePolicies(swIfIndex, tapConf, 0)
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
		h.server.log.Infof("policy(upd) interface swif=%d conf=%v", swIfIndex, forwardConf)
		err = vpp.ConfigurePolicies(swIfIndex, forwardConf, 1 /* invertRxTx */)
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
		h.server.log.Infof("policy(upd) interface swif=%d conf=%v", swIfIndex, tapConf)
		err = vpp.ConfigurePolicies(swIfIndex, tapConf, 0)
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
	for _, swIfIndex := range append(h.UplinkSwIfIndexes, h.TunnelSwIfIndexes...) {
		// Unconfigure forward policies
		h.server.log.Infof("policy(del) interface swif=%d", swIfIndex)
		err = vpp.ConfigurePolicies(swIfIndex, types.NewInterfaceConfig(), 0)
		if err != nil {
			return errors.Wrapf(err, "cannot unconfigure policies on interface %d", swIfIndex)
		}
	}
	for _, swIfIndex := range h.TapSwIfIndexes {
		// Unconfigure tap0 policies
		h.server.log.Infof("policy(del) interface swif=%d", swIfIndex)
		conf := types.NewInterfaceConfig()
		conf.IngressPolicyIDs = h.server.defaultTap0IngressConf
		conf.EgressPolicyIDs = h.server.defaultTap0EgressConf
		err = vpp.ConfigurePolicies(swIfIndex, conf, 0)
		if err != nil {
			return errors.Wrapf(err, "cannot unconfigure policies on interface %d", swIfIndex)
		}
	}
	h.UplinkSwIfIndexes = []uint32{}
	h.TapSwIfIndexes = []uint32{}
	h.TunnelSwIfIndexes = []uint32{}
	return nil
}
