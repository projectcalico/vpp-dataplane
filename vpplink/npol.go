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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/npol"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) IpsetCreate(ipsetType types.IpsetType) (setID uint32, err error) {
	client := npol.NewServiceClient(v.GetConnection())

	response, err := client.NpolIpsetCreate(v.GetContext(), &npol.NpolIpsetCreate{
		Type: npol.NpolIpsetType(ipsetType),
	})
	if err != nil {
		return 0, fmt.Errorf("npolIpsetCreate failed: %w", err)
	}
	return response.SetID, nil
}

func (v *VppLink) IpsetDelete(ipsetID uint32) error {
	client := npol.NewServiceClient(v.GetConnection())

	_, err := client.NpolIpsetDelete(v.GetContext(), &npol.NpolIpsetDelete{
		SetID: ipsetID,
	})
	if err != nil {
		return fmt.Errorf("npolIpsetDelete failed: %w", err)
	}
	return nil
}

func (v *VppLink) addDelIpsetMembers(ipsetID uint32, isAdd bool, members []npol.NpolIpsetMember) error {
	client := npol.NewServiceClient(v.GetConnection())

	_, err := client.NpolIpsetAddDelMembers(v.GetContext(), &npol.NpolIpsetAddDelMembers{
		SetID:   ipsetID,
		IsAdd:   isAdd,
		Len:     uint32(len(members)),
		Members: members,
	})
	if err != nil {
		return fmt.Errorf("npolIpsetAddDelMembers failed: %w", err)
	}
	return nil
}

func (v *VppLink) addDelIpsetIPMembers(ipsetID uint32, isAdd bool, members []net.IP) (err error) {
	unions := make([]npol.NpolIpsetMember, len(members))
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
	unions := make([]npol.NpolIpsetMember, len(members))
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
	unions := make([]npol.NpolIpsetMember, len(members))
	for i, m := range members {
		unions[i].Val.SetTuple(npol.NpolThreeTuple{
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

func (v *VppLink) RuleCreate(rule *types.Rule) (ruleID uint32, err error) {
	client := npol.NewServiceClient(v.GetConnection())

	response, err := client.NpolRuleCreate(v.GetContext(), &npol.NpolRuleCreate{
		Rule: types.ToNpolRule(rule),
	})
	if err != nil {
		return 0, fmt.Errorf("npolRuleCreate failed: %w", err)
	}
	return response.RuleID, nil
}

func (v *VppLink) RuleUpdate(ruleID uint32, rule *types.Rule) error {
	client := npol.NewServiceClient(v.GetConnection())

	_, err := client.NpolRuleUpdate(v.GetContext(), &npol.NpolRuleUpdate{
		RuleID: ruleID,
		Rule:   types.ToNpolRule(rule),
	})
	if err != nil {
		return fmt.Errorf("npolRuleUpdate failed: %w", err)
	}
	return nil
}

func (v *VppLink) RuleDelete(ruleID uint32) error {
	client := npol.NewServiceClient(v.GetConnection())

	_, err := client.NpolRuleDelete(v.GetContext(), &npol.NpolRuleDelete{
		RuleID: ruleID,
	})
	if err != nil {
		return fmt.Errorf("npolRuleDelete failed: %w", err)
	}
	return nil
}

func (v *VppLink) PolicyCreate(policy *types.Policy) (policyID uint32, err error) {
	client := npol.NewServiceClient(v.GetConnection())

	response, err := client.NpolPolicyCreate(v.GetContext(), &npol.NpolPolicyCreate{
		Rules: types.ToNpolPolicy(policy),
	})
	if err != nil {
		return 0, fmt.Errorf("npolPolicyCreate failed: %w", err)
	}
	return response.PolicyID, nil
}

func (v *VppLink) PolicyUpdate(policyID uint32, policy *types.Policy) error {
	client := npol.NewServiceClient(v.GetConnection())

	_, err := client.NpolPolicyUpdate(v.GetContext(), &npol.NpolPolicyUpdate{
		PolicyID: policyID,
		Rules:    types.ToNpolPolicy(policy),
	})
	if err != nil {
		return fmt.Errorf("npolPolicyUpdate failed: %w", err)
	}
	return nil
}

func (v *VppLink) PolicyDelete(policyID uint32) error {
	client := npol.NewServiceClient(v.GetConnection())

	_, err := client.NpolPolicyDelete(v.GetContext(), &npol.NpolPolicyDelete{
		PolicyID: policyID,
	})
	if err != nil {
		return fmt.Errorf("npolPolicyDelete failed: %w", err)
	}
	return nil
}

func (v *VppLink) ConfigurePolicies(swIfIndex uint32, conf *types.InterfaceConfig, invertRxTx uint8) error {
	client := npol.NewServiceClient(v.GetConnection())

	// In the calico agent, policies are expressed from the point of view of PODs
	// in VPP this is reversed
	rxPolicyIDs := conf.EgressPolicyIDs
	txPolicyIDs := conf.IngressPolicyIDs
	profileIDs := conf.ProfileIDs

	ids := append(rxPolicyIDs, txPolicyIDs...)
	ids = append(ids, profileIDs...)
	_, err := client.NpolConfigurePolicies(v.GetContext(), &npol.NpolConfigurePolicies{
		SwIfIndex:        swIfIndex,
		NumRxPolicies:    uint32(len(rxPolicyIDs)),
		NumTxPolicies:    uint32(len(txPolicyIDs)),
		TotalIds:         uint32(len(rxPolicyIDs) + len(txPolicyIDs) + len(profileIDs)),
		PolicyIds:        ids,
		InvertRxTx:       invertRxTx,
		PolicyDefaultRx:  conf.PolicyDefaultRx,
		PolicyDefaultTx:  conf.PolicyDefaultTx,
		ProfileDefaultRx: conf.ProfileDefaultRx,
		ProfileDefaultTx: conf.ProfileDefaultTx,
	})
	if err != nil {
		return fmt.Errorf("npolConfigurePolicies failed: %w", err)
	}
	return nil
}
