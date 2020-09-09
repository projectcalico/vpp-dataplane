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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/capo"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) IpsetCreate(ipsetType types.IpsetType) (setId uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoIpsetCreateReply{}
	request := &capo.CapoIpsetCreate{
		Type: capo.CapoIpsetType(ipsetType),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return types.InvalidID, errors.Wrapf(err, "CapoIpsetCreate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return types.InvalidID, fmt.Errorf("CapoIpsetCreate failed: req %+v reply %+v", request, response)
	}
	return response.SetID, nil
}

func (v *VppLink) IpsetDelete(ipsetID uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoIpsetDeleteReply{}
	request := &capo.CapoIpsetDelete{
		SetID: ipsetID,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoIpsetDelete failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoIpsetDelete failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) addDelIpsetMembers(ipsetID uint32, isAdd bool, members []capo.CapoIpsetMember) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoIpsetAddDelMembersReply{}
	request := &capo.CapoIpsetAddDelMembers{
		SetID:   ipsetID,
		IsAdd:   isAdd,
		Members: members,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoIpsetAddDelMembers failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoIpsetAddDelMembers failed: req %+v reply %+v", request, response)
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

func (v *VppLink) RuleCreate(rule types.Rule) (ruleId uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoRuleCreateReply{}
	request := &capo.CapoRuleCreate{
		Rule: types.ToCapoRule(rule),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return types.InvalidID, errors.Wrapf(err, "CapoRuleCreate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return types.InvalidID, fmt.Errorf("CapoRuleCreate failed: req %+v reply %+v", request, response)
	}
	return response.RuleID, nil
}

func (v *VppLink) RuleUpdate(ruleId uint32, rule types.Rule) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoRuleUpdateReply{}
	request := &capo.CapoRuleUpdate{
		RuleID: ruleId,
		Rule:   types.ToCapoRule(rule),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoRuleUpdate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoRuleUpdate failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) RuleDelete(ruleId uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoRuleDeleteReply{}
	request := &capo.CapoRuleDelete{
		RuleID: ruleId,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoRuleDelete failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoRuleDelete failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) PolicyCreate(policy types.Policy) (policyId uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoPolicyCreateReply{}
	request := &capo.CapoPolicyCreate{
		Rules: types.ToCapoPolicy(policy),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return types.InvalidID, errors.Wrapf(err, "CapoPolicyCreate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return types.InvalidID, fmt.Errorf("CapoPolicyCreate failed: req %+v reply %+v", request, response)
	}
	return response.PolicyID, nil
}

func (v *VppLink) PolicyUpdate(policyId uint32, policy types.Policy) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoPolicyUpdateReply{}
	request := &capo.CapoPolicyUpdate{
		PolicyID: policyId,
		Rules:    types.ToCapoPolicy(policy),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoPolicyUpdate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoPolicyUpdate failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) PolicyDelete(policyId uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoPolicyDeleteReply{}
	request := &capo.CapoPolicyDelete{
		PolicyID: policyId,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoPolicyDelete failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoPolicyDelete failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) ConfigurePolicies(swIfIndex uint32, passId uint32, policies []uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &capo.CapoConfigurePoliciesReply{}
	request := &capo.CapoConfigurePolicies{
		SwIfIndex:    swIfIndex,
		PassPolicyID: passId,
		PolicyIds:    policies,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CapoPolicyDelete failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CapoPolicyDelete failed: req %+v reply %+v", request, response)
	}
	return nil
}
