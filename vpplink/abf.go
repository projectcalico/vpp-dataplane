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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/abf"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/fib_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

var (
	policyIndexAllocator = NewIndexAllocator(1 /*StartIndex*/)
)

func (v *VppLink) attachDetachAbfPolicy(policyID uint32, swIfIndex uint32, isv6 bool, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &abf.AbfItfAttachAddDelReply{}
	request := &abf.AbfItfAttachAddDel{
		IsAdd: isAdd,
		Attach: abf.AbfItfAttach{
			PolicyID:  policyID,
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			IsIPv6:    isv6,
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	opStr := "Detach"
	if isAdd {
		opStr = "Attach"
	}
	if err != nil {
		return errors.Wrapf(err, "%s Abf Policy failed", opStr)
	} else if response.Retval != 0 {
		return fmt.Errorf("%s Abf Policy failed with retval %d", opStr, response.Retval)
	}
	return nil
}

func (v *VppLink) AttachAbfPolicy(policyID uint32, swIfIndex uint32, isv6 bool) (err error) {
	return v.attachDetachAbfPolicy(policyID, swIfIndex, isv6, true)
}

func (v *VppLink) DetachAbfPolicy(policyID uint32, swIfIndex uint32, isv6 bool) (err error) {
	return v.attachDetachAbfPolicy(policyID, swIfIndex, isv6, false)
}

func (v *VppLink) addDelAbfPolicy(policy *types.AbfPolicy, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	paths := make([]fib_types.FibPath, 0, len(policy.Paths))
	for _, routePath := range policy.Paths {
		paths = append(paths, routePath.ToFibPath(false /*isip6*/))
	}

	response := &abf.AbfPolicyAddDelReply{}
	request := &abf.AbfPolicyAddDel{
		IsAdd: isAdd,
		Policy: abf.AbfPolicy{
			PolicyID: policy.PolicyID,
			ACLIndex: policy.AclIndex,
			Paths:    paths,
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	opStr := "Del"
	if isAdd {
		opStr = "Add"
	}
	if err != nil {
		return errors.Wrapf(err, "%s Abf Policy failed", opStr)
	} else if response.Retval != 0 {
		return fmt.Errorf("%s Abf Policy failed with retval %d", opStr, response.Retval)
	}
	return nil
}

func (v *VppLink) AddAbfPolicy(policy *types.AbfPolicy) (err error) {
	policy.PolicyID = policyIndexAllocator.AllocateIndex()
	return v.addDelAbfPolicy(policy, true)
}

func (v *VppLink) DelAbfPolicy(policy *types.AbfPolicy) (err error) {
	err = v.addDelAbfPolicy(policy, false)
	if err != nil {
		policyIndexAllocator.FreeIndex(policy.PolicyID)
	}
	return err
}
