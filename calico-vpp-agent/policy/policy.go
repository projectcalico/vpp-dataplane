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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type PolicyID struct {
	Tier string
	Name string
}

// Policy represents both Policies and Profiles in the calico API
type Policy struct {
	*types.Policy
	VppID         uint32
	InboundRules  []*Rule
	OutboundRules []*Rule
}

func fromProtoPolicy(p *proto.Policy) (policy *Policy, err error) {
	policy = &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	if p.Untracked {
		return nil, fmt.Errorf("Untracked policies not supported")
	}
	if !p.PreDnat && len(p.OutboundRules) > 0 {
		return nil, fmt.Errorf("post dnat outbound policies not supported")
	}
	for _, r := range p.InboundRules {
		rule, err := fromProtoRule(r)
		if err != nil {
			return nil, err
		}
		policy.InboundRules = append(policy.InboundRules, rule)
	}
	for _, r := range p.OutboundRules {
		rule, err := fromProtoRule(r)
		if err != nil {
			return nil, err
		}
		policy.OutboundRules = append(policy.OutboundRules, rule)
	}
	return policy, nil
}

func fromProtoProfile(p *proto.Profile) (profile *Policy, err error) {
	profile = &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	for _, r := range p.InboundRules {
		rule, err := fromProtoRule(r)
		if err != nil {
			return nil, err
		}
		profile.InboundRules = append(profile.InboundRules, rule)
	}
	for _, r := range p.OutboundRules {
		rule, err := fromProtoRule(r)
		if err != nil {
			return nil, err
		}
		profile.OutboundRules = append(profile.OutboundRules, rule)
	}
	return profile, nil
}

func (p *Policy) createRules(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	p.InboundRuleIDs = make([]uint32, 0, len(p.InboundRules))
	for _, rule := range p.InboundRules {
		err := rule.Create(vpp, state)
		if err != nil {
			return err
		}
		p.InboundRuleIDs = append(p.InboundRuleIDs, rule.VppID)
	}
	p.OutboundRuleIDs = make([]uint32, 0, len(p.OutboundRules))
	for _, rule := range p.OutboundRules {
		err := rule.Create(vpp, state)
		if err != nil {
			return err
		}
		p.OutboundRuleIDs = append(p.OutboundRuleIDs, rule.VppID)
	}
	return nil
}

func (p *Policy) deleteRules(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	for _, rule := range p.InboundRules {
		err = rule.Delete(vpp)
		if err != nil {
			return err
		}
	}
	for _, rule := range p.OutboundRules {
		err = rule.Delete(vpp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) Create(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	err = p.createRules(vpp, state)
	if err != nil {
		return errors.Wrap(err, "cannot create rules for policy")
	}
	id, err := vpp.PolicyCreate(p.Policy)
	if err != nil {
		return errors.Wrap(err, "cannot create policy")
	}
	p.VppID = id
	return nil
}

// Apply any changes to VPP and update this policy to new
func (p *Policy) Update(vpp *vpplink.VppLink, new *Policy, state *PolicyState) (err error) {
	// Start by creating new rules
	err = new.createRules(vpp, state)
	if err != nil {
		return errors.Wrap(err, "cannot create rules for policy")
	}

	// Update policy
	err = vpp.PolicyUpdate(p.VppID, new.Policy)
	if err != nil {
		return errors.Wrap(err, "cannot update policy")
	}

	// Delete old rules
	err = p.deleteRules(vpp, state)
	if err != nil {
		return errors.Wrap(err, "cannot delete old rules for policy")
	}

	// Update policy record
	p.InboundRules = new.InboundRules
	p.InboundRuleIDs = new.InboundRuleIDs
	p.OutboundRules = new.OutboundRules
	p.OutboundRuleIDs = new.OutboundRuleIDs
	return nil
}

func (p *Policy) Delete(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	// Delete all accompanying rules
	err = p.deleteRules(vpp, state)
	if err != nil {
		return errors.Wrap(err, "cannot delete old rules for policy")
	}
	err = vpp.PolicyDelete(p.VppID)
	if err != nil {
		return errors.Wrap(err, "cannot delete policy")
	}
	p.VppID = types.InvalidID
	return nil
}
