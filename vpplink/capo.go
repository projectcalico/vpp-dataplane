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

package vpplink

import (
	"fmt"
	"net"

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/capo"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) IpsetCreate(ipsetType types.IpsetType) (setId uint32, err error) {
	client := capo.NewServiceClient(v.GetConnection())

	response, err := client.CapoIpsetCreate(v.GetContext(), &capo.CapoIpsetCreate{
		Type: capo.CapoIpsetType(ipsetType),
	})
	if err != nil {
		return 0, fmt.Errorf("CapoIpsetCreate failed: %w", err)
	}
	return response.SetID, nil
}

func (v *VppLink) IpsetDelete(ipsetID uint32) error {
	client := capo.NewServiceClient(v.GetConnection())

	_, err := client.CapoIpsetDelete(v.GetContext(), &capo.CapoIpsetDelete{
		SetID: ipsetID,
	})
	if err != nil {
		return fmt.Errorf("CapoIpsetDelete failed: %w", err)
	}
	return nil
}

func (v *VppLink) addDelIpsetMembers(ipsetID uint32, isAdd bool, members []capo.CapoIpsetMember) error {
	client := capo.NewServiceClient(v.GetConnection())

	_, err := client.CapoIpsetAddDelMembers(v.GetContext(), &capo.CapoIpsetAddDelMembers{
		SetID:   ipsetID,
		IsAdd:   isAdd,
		Len:     uint32(len(members)),
		Members: members,
	})
	if err != nil {
		return fmt.Errorf("CapoIpsetAddDelMembers failed: %w", err)
	}
	return nil
}

func (v *VppLink) addDelIpsetIPMembers(ipsetID uint32, isAdd bool, members []net.IP) (err error) {
	unions := make([]capo.CapoIpsetMember, len(members))
	for i, m := range members {
		unions[i].Val.SetAddress(types.ToVppAddress(m))
	}
	return v.addDelIpsetMembers(ipsetID, isAdd, unions)
}

func (v *VppLink) AddIpsetIPMembers(ipsetID uint32, members []net.IP) (err error) {
	return v.addDelIpsetIPMembers(ipsetID, true, members)
}

func (v *VppLink) DelIpsetIPMembers(ipsetID uint32, members []net.IP) (err error) {
	return v.addDelIpsetIPMembers(ipsetID, false, members)
}

func (v *VppLink) addDelIpsetNetMembers(ipsetID uint32, isAdd bool, members []*net.IPNet) (err error) {
	unions := make([]capo.CapoIpsetMember, len(members))
	for i, m := range members {
		unions[i].Val.SetPrefix(types.ToVppPrefix(m))
	}
	return v.addDelIpsetMembers(ipsetID, isAdd, unions)
}

func (v *VppLink) AddIpsetNetMembers(ipsetID uint32, members []*net.IPNet) (err error) {
	return v.addDelIpsetNetMembers(ipsetID, true, members)
}

func (v *VppLink) DelIpsetNetMembers(ipsetID uint32, members []*net.IPNet) (err error) {
	return v.addDelIpsetNetMembers(ipsetID, false, members)
}

func (v *VppLink) addDelIpsetIPPortMembers(ipsetID uint32, isAdd bool, members []types.IPPort) (err error) {
	unions := make([]capo.CapoIpsetMember, len(members))
	for i, m := range members {
		unions[i].Val.SetTuple(capo.CapoThreeTuple{
			Address: types.ToVppAddress(m.Addr),
			L4Proto: m.L4Proto,
			Port:    m.Port,
		})
	}
	return v.addDelIpsetMembers(ipsetID, isAdd, unions)
}

func (v *VppLink) AddIpsetIPPortMembers(ipsetID uint32, members []types.IPPort) (err error) {
	return v.addDelIpsetIPPortMembers(ipsetID, true, members)
}

func (v *VppLink) DelIpsetIPPortMembers(ipsetID uint32, members []types.IPPort) (err error) {
	return v.addDelIpsetIPPortMembers(ipsetID, false, members)
}

func (v *VppLink) RuleCreate(rule *types.Rule) (ruleId uint32, err error) {
	client := capo.NewServiceClient(v.GetConnection())

	response, err := client.CapoRuleCreate(v.GetContext(), &capo.CapoRuleCreate{
		Rule: types.ToCapoRule(rule),
	})
	if err != nil {
		return 0, fmt.Errorf("CapoRuleCreate failed: %w", err)
	}
	return response.RuleID, nil
}

func (v *VppLink) RuleUpdate(ruleId uint32, rule *types.Rule) error {
	client := capo.NewServiceClient(v.GetConnection())

	_, err := client.CapoRuleUpdate(v.GetContext(), &capo.CapoRuleUpdate{
		RuleID: ruleId,
		Rule:   types.ToCapoRule(rule),
	})
	if err != nil {
		return fmt.Errorf("CapoRuleUpdate failed: %w", err)
	}
	return nil
}

func (v *VppLink) RuleDelete(ruleId uint32) error {
	client := capo.NewServiceClient(v.GetConnection())

	_, err := client.CapoRuleDelete(v.GetContext(), &capo.CapoRuleDelete{
		RuleID: ruleId,
	})
	if err != nil {
		return fmt.Errorf("CapoRuleDelete failed: %w", err)
	}
	return nil
}

func (v *VppLink) PolicyCreate(policy *types.Policy) (policyId uint32, err error) {
	client := capo.NewServiceClient(v.GetConnection())

	response, err := client.CapoPolicyCreate(v.GetContext(), &capo.CapoPolicyCreate{
		Rules: types.ToCapoPolicy(policy),
	})
	if err != nil {
		return 0, fmt.Errorf("CapoPolicyCreate failed: %w", err)
	}
	return response.PolicyID, nil
}

func (v *VppLink) PolicyUpdate(policyId uint32, policy *types.Policy) error {
	client := capo.NewServiceClient(v.GetConnection())

	_, err := client.CapoPolicyUpdate(v.GetContext(), &capo.CapoPolicyUpdate{
		PolicyID: policyId,
		Rules:    types.ToCapoPolicy(policy),
	})
	if err != nil {
		return fmt.Errorf("CapoPolicyUpdate failed: %w", err)
	}
	return nil
}

func (v *VppLink) PolicyDelete(policyId uint32) error {
	client := capo.NewServiceClient(v.GetConnection())

	_, err := client.CapoPolicyDelete(v.GetContext(), &capo.CapoPolicyDelete{
		PolicyID: policyId,
	})
	if err != nil {
		return fmt.Errorf("CapoPolicyDelete failed: %w", err)
	}
	return nil
}

func (v *VppLink) ConfigurePolicies(swIfIndex uint32, conf *types.InterfaceConfig, invertRxTx uint8) error {
	client := capo.NewServiceClient(v.GetConnection())

	// In the calico agent, policies are expressed from the point of view of PODs
	// in VPP this is reversed
	rxPolicyIDs := conf.EgressPolicyIDs
	txPolicyIDs := conf.IngressPolicyIDs
	profileIDs := conf.ProfileIDs

	ids := append(rxPolicyIDs, txPolicyIDs...)
	ids = append(ids, profileIDs...)
	_, err := client.CapoConfigurePolicies(v.GetContext(), &capo.CapoConfigurePolicies{
		SwIfIndex:     swIfIndex,
		NumRxPolicies: uint32(len(rxPolicyIDs)),
		NumTxPolicies: uint32(len(txPolicyIDs)),
		TotalIds:      uint32(len(rxPolicyIDs) + len(txPolicyIDs) + len(profileIDs)),
		PolicyIds:     ids,
		InvertRxTx:    invertRxTx,
	})
	if err != nil {
		return fmt.Errorf("CapoConfigurePolicies failed: %w", err)
	}
	return nil
}
