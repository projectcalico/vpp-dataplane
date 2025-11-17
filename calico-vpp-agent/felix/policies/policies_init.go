// Copyright (C) 2025 Cisco Systems Inc.
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
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/npol"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (s *PoliciesHandler) createAllPodsIpset() (err error) {
	ipset := NewIPSet()
	err = ipset.Create(s.vpp)
	if err != nil {
		return err
	}
	s.allPodsIpset = ipset
	return nil
}

// createAllowFromHostPolicy creates a policy allowing host->pod communications. This is needed
// to maintain vanilla Calico's behavior where the host can always reach pods.
// This policy is applied in Egress on the host endpoint tap (i.e. linux -> VPP)
// and on the Ingress of Workload endpoints (i.e. VPP -> pod)
func (s *PoliciesHandler) createAllowFromHostPolicy() (err error) {
	s.log.Infof("Creating rules to allow traffic from host to pods with egress policies")
	ruleOut := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-egressallowfromhost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
		},
		DstIPSetNames: []string{"calico-vpp-wep-addr-ipset"},
	}
	ps := PolicyState{IPSets: map[string]*IPSet{"calico-vpp-wep-addr-ipset": s.allPodsIpset}}
	s.log.Infof("Creating rules to allow traffic from host to pods with ingress policies")
	ruleIn := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-ingressallowfromhost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			SrcNet: []net.IPNet{},
		},
	}
	if s.cache.GetNodeIP4() != nil {
		ruleIn.SrcNet = append(ruleIn.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP4()))
	}
	if s.cache.GetNodeIP6() != nil {
		ruleIn.SrcNet = append(ruleIn.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP6()))
	}

	allowFromHostPolicy := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	allowFromHostPolicy.OutboundRules = append(allowFromHostPolicy.OutboundRules, ruleOut)
	allowFromHostPolicy.InboundRules = append(allowFromHostPolicy.InboundRules, ruleIn)
	if s.AllowFromHostPolicy == nil {
		err = allowFromHostPolicy.Create(s.vpp, &ps)
	} else {
		allowFromHostPolicy.VppID = s.AllowFromHostPolicy.VppID
		err = s.AllowFromHostPolicy.Update(s.vpp, allowFromHostPolicy, &ps)
	}
	s.AllowFromHostPolicy = allowFromHostPolicy
	if err != nil {
		return errors.Wrap(err, "cannot create policy to allow traffic from host to pods")
	}
	s.log.Infof("Created allow from host to pods traffic with ID: %+v", s.AllowFromHostPolicy.VppID)
	return nil
}

func (s *PoliciesHandler) createEndpointToHostPolicy( /*may be return*/ ) (err error) {
	workloadsToHostPolicy := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	workloadsToHostRule := &Rule{
		VppID: types.InvalidID,
		Rule: &types.Rule{
			Action: s.getEndpointToHostAction(),
		},
		SrcIPSetNames: []string{"calico-vpp-wep-addr-ipset"},
	}
	ps := PolicyState{
		IPSets: map[string]*IPSet{
			"calico-vpp-wep-addr-ipset": s.allPodsIpset,
		},
	}
	workloadsToHostPolicy.InboundRules = append(workloadsToHostPolicy.InboundRules, workloadsToHostRule)

	err = workloadsToHostPolicy.Create(s.vpp, &ps)
	if err != nil {
		return err
	}
	s.workloadsToHostPolicy = workloadsToHostPolicy

	conf := types.NewInterfaceConfig()
	conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, s.workloadsToHostPolicy.VppID)
	conf.PolicyDefaultTx = npol.NPOL_DEFAULT_ALLOW
	conf.PolicyDefaultRx = npol.NPOL_DEFAULT_ALLOW
	swifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("host-") // tap0 interfaces
	if err != nil {
		s.log.Error(err)
	}
	for _, swifindex := range swifindexes {
		err = s.vpp.ConfigurePolicies(uint32(swifindex), conf, 0)
		if err != nil {
			s.log.Error("cannot create policy to drop traffic to host")
		}
	}
	s.defaultTap0IngressConf = conf.IngressPolicyIDs
	s.defaultTap0EgressConf = conf.EgressPolicyIDs
	return nil
}

// createFailSafePolicies ensures the failsafe policies defined in the Felixconfiguration exist in VPP.
// check https://github.com/projectcalico/calico/blob/master/felix/rules/static.go :: failsafeInChain for the linux implementation
// To be noted. This does not implement the doNotTrack case as we do not yet support doNotTrack
func (s *PoliciesHandler) createFailSafePolicies() (err error) {
	failSafePol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}

	if len(s.cache.FelixConfig.FailsafeInboundHostPorts) != 0 {
		for _, protoPort := range s.cache.FelixConfig.FailsafeInboundHostPorts {
			protocol, err := ParseProtocol(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: protoPort.Protocol}})
			if err != nil {
				s.log.WithError(err).Error("Failed to parse protocol in inbound failsafe rule. Skipping failsafe rule")
				continue
			}
			rule := &Rule{
				VppID:  types.InvalidID,
				RuleID: fmt.Sprintf("failsafe-in-%s-%s-%d", protoPort.Net, protoPort.Protocol, protoPort.Port),
				Rule: &types.Rule{
					Action: types.ActionAllow,
					// Ports are always filtered on the destination of packets
					DstPortRange: []types.PortRange{{First: protoPort.Port, Last: protoPort.Port}},
					Filters: []types.RuleFilter{{
						ShouldMatch: true,
						Type:        types.NpolFilterProto,
						Value:       int(protocol),
					}},
				},
			}
			if protoPort.Net != "" {
				_, protoPortNet, err := net.ParseCIDR(protoPort.Net)
				if err != nil {
					s.log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
					continue
				}
				// Inbound packets are checked for where they come FROM
				rule.SrcNet = append(rule.SrcNet, *protoPortNet)
			}
			failSafePol.InboundRules = append(failSafePol.InboundRules, rule)
		}
	}

	if len(s.cache.FelixConfig.FailsafeOutboundHostPorts) != 0 {
		for _, protoPort := range s.cache.FelixConfig.FailsafeOutboundHostPorts {
			protocol, err := ParseProtocol(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: protoPort.Protocol}})
			if err != nil {
				s.log.WithError(err).Error("Failed to parse protocol in outbound failsafe rule. Skipping failsafe rule")
				continue
			}
			rule := &Rule{
				VppID:  types.InvalidID,
				RuleID: fmt.Sprintf("failsafe-out-%s-%s-%d", protoPort.Net, protoPort.Protocol, protoPort.Port),
				Rule: &types.Rule{
					Action: types.ActionAllow,
					// Ports are always filtered on the destination of packets
					DstPortRange: []types.PortRange{{First: protoPort.Port, Last: protoPort.Port}},
					Filters: []types.RuleFilter{{
						ShouldMatch: true,
						Type:        types.NpolFilterProto,
						Value:       int(protocol),
					}},
				},
			}
			if protoPort.Net != "" {
				_, protoPortNet, err := net.ParseCIDR(protoPort.Net)
				if err != nil {
					s.log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
					continue
				}
				// Outbound packets are checked for where they go TO
				rule.DstNet = append(rule.DstNet, *protoPortNet)
			}
			failSafePol.OutboundRules = append(failSafePol.OutboundRules, rule)
		}
	}

	if s.failSafePolicy == nil {
		err = failSafePol.Create(s.vpp, nil)

	} else {
		failSafePol.VppID = s.failSafePolicy.VppID
		err = s.failSafePolicy.Update(s.vpp, failSafePol, nil)
	}
	if err != nil {
		return err
	}
	s.failSafePolicy = failSafePol
	s.log.Infof("Created failsafe policy with ID %+v", s.failSafePolicy.VppID)
	return nil
}

func (s *PoliciesHandler) createAllowToHostPolicy() (err error) {
	s.log.Infof("Creating policy to allow traffic to host that is applied on uplink")
	ruleIn := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowtohost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			DstNet: []net.IPNet{},
		},
	}
	ruleOut := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowtohost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			SrcNet: []net.IPNet{},
		},
	}
	if s.cache.GetNodeIP4() != nil {
		ruleIn.DstNet = append(ruleIn.DstNet, *common.FullyQualified(*s.cache.GetNodeIP4()))
		ruleOut.SrcNet = append(ruleOut.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP4()))
	}
	if s.cache.GetNodeIP6() != nil {
		ruleIn.DstNet = append(ruleIn.DstNet, *common.FullyQualified(*s.cache.GetNodeIP6()))
		ruleOut.SrcNet = append(ruleOut.SrcNet, *common.FullyQualified(*s.cache.GetNodeIP6()))
	}

	allowToHostPolicy := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	allowToHostPolicy.InboundRules = append(allowToHostPolicy.InboundRules, ruleIn)
	allowToHostPolicy.OutboundRules = append(allowToHostPolicy.OutboundRules, ruleOut)
	if s.allowToHostPolicy == nil {
		err = allowToHostPolicy.Create(s.vpp, nil)
	} else {
		allowToHostPolicy.VppID = s.allowToHostPolicy.VppID
		err = s.allowToHostPolicy.Update(s.vpp, allowToHostPolicy, nil)
	}
	s.allowToHostPolicy = allowToHostPolicy
	if err != nil {
		return errors.Wrap(err, "cannot create policy to allow traffic to host")
	}
	s.log.Infof("Created policy to allow traffic to host with ID: %+v", s.allowToHostPolicy.VppID)
	return nil
}

func (s *PoliciesHandler) PoliciesHandlerInit() error {
	err := s.createAllPodsIpset()
	if err != nil {
		return errors.Wrap(err, "Error in createallPodsIpset")
	}
	err = s.createEndpointToHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createEndpointToHostPolicy")
	}
	err = s.createAllowFromHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in creating AllowFromHostPolicy")
	}
	err = s.createAllowToHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createAllowToHostPolicy")
	}
	err = s.createFailSafePolicies()
	if err != nil {
		return errors.Wrap(err, "Error in createFailSafePolicies")
	}
	s.interfacesMap, err = mapTagToInterfaceDetails(s.vpp)
	if err != nil {
		return errors.Wrap(err, "Error in mapping uplink to tap interfaces")
	}
	return nil
}
