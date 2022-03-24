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
	vppacl "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/acl"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/acl_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) AddACL(acl *types.ACL) (err error) {
	v.Lock()
	defer v.Unlock()

	rules := make([]acl_types.ACLRule, 0, len(acl.Rules))
	for _, aclRule := range acl.Rules {
		rules = append(rules, aclRule.ToVppACLRule())
	}

	response := &vppacl.ACLAddReplaceReply{}
	request := &vppacl.ACLAddReplace{
		ACLIndex: ^uint32(0),
		Tag:      acl.Tag,
		R:        rules,
		Count:    uint32(len(rules)),
	}
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Add ACL failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add ACL failed with retval %d", response.Retval)
	}
	acl.ACLIndex = response.ACLIndex
	return nil
}

func (v *VppLink) DelACL(aclIndex uint32) (err error) {
	v.Lock()
	defer v.Unlock()

	response := &vppacl.ACLDelReply{}
	request := &vppacl.ACLDel{
		ACLIndex: aclIndex,
	}
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del ACL failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Del ACL failed with retval %d", response.Retval)
	}
	return nil
}
