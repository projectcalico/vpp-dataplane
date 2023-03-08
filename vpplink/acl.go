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

	vppacl "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/acl"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/acl_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) AddACL(acl *types.ACL) error {
	client := vppacl.NewServiceClient(v.GetConnection())

	rules := make([]acl_types.ACLRule, 0, len(acl.Rules))
	for _, aclRule := range acl.Rules {
		rules = append(rules, aclRule.ToVppACLRule())
	}

	response, err := client.ACLAddReplace(v.GetContext(), &vppacl.ACLAddReplace{
		ACLIndex: ^uint32(0),
		Tag:      acl.Tag,
		R:        rules,
		Count:    uint32(len(rules)),
	})
	if err != nil {
		return fmt.Errorf("failed to add ACL: %w", err)
	}
	acl.ACLIndex = response.ACLIndex
	return nil
}

func (v *VppLink) DelACL(aclIndex uint32) error {
	client := vppacl.NewServiceClient(v.GetConnection())

	_, err := client.ACLDel(v.GetContext(), &vppacl.ACLDel{
		ACLIndex: aclIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to delete ACL: %w", err)
	}
	return nil
}
