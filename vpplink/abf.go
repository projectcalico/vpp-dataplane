// Copyright (C) 2021 Cisco Systems Inc.
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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/abf"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/fib_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

var (
	policyIndexAllocator = NewIndexAllocator(1)
)

func (v *VppLink) attachDetachAbfPolicy(policyID uint32, swIfIndex uint32, isv6 bool, isAdd bool) error {
	client := abf.NewServiceClient(v.GetConnection())

	_, err := client.AbfItfAttachAddDel(v.GetContext(), &abf.AbfItfAttachAddDel{
		IsAdd: isAdd,
		Attach: abf.AbfItfAttach{
			PolicyID:  policyID,
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			IsIPv6:    isv6,
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) AttachAbfPolicy(policyID uint32, swIfIndex uint32, isv6 bool) error {
	if err := v.attachDetachAbfPolicy(policyID, swIfIndex, isv6, true); err != nil {
		return fmt.Errorf("failed to attach ABF Policy: %w", err)
	}
	return nil
}

func (v *VppLink) DetachAbfPolicy(policyID uint32, swIfIndex uint32, isv6 bool) error {
	if err := v.attachDetachAbfPolicy(policyID, swIfIndex, isv6, false); err != nil {
		return fmt.Errorf("failed to detach ABF Policy: %w", err)
	}
	return nil
}

func (v *VppLink) addDelAbfPolicy(policy *types.AbfPolicy, isAdd bool) error {
	client := abf.NewServiceClient(v.GetConnection())

	fibPaths := make([]fib_types.FibPath, 0, len(policy.Paths))
	for _, path := range policy.Paths {
		fibPaths = append(fibPaths, path.ToFibPath(false))
	}

	_, err := client.AbfPolicyAddDel(v.GetContext(), &abf.AbfPolicyAddDel{
		IsAdd: isAdd,
		Policy: abf.AbfPolicy{
			PolicyID: policy.PolicyID,
			ACLIndex: policy.ACLIndex,
			Paths:    fibPaths,
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) AddAbfPolicy(policy *types.AbfPolicy) error {
	policy.PolicyID = policyIndexAllocator.AllocateIndex()
	if err := v.addDelAbfPolicy(policy, true); err != nil {
		return fmt.Errorf("failed to add ABF Policy: %w", err)
	}
	return nil
}

func (v *VppLink) DelAbfPolicy(policy *types.AbfPolicy) error {
	if err := v.addDelAbfPolicy(policy, false); err != nil {
		return fmt.Errorf("failed to delete ABF Policy: %w", err)
	}
	policyIndexAllocator.FreeIndex(policy.PolicyID)
	return nil
}
