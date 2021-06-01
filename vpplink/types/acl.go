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

package types

import (
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/acl_types"
	"net"
)

type ACLRule struct {
	Src   net.IPNet
	Dst   net.IPNet
	Proto IPProto
}

func (r *ACLRule) ToVppACLRule() acl_types.ACLRule {
	return acl_types.ACLRule{
		IsPermit:  acl_types.ACL_ACTION_API_PERMIT,
		SrcPrefix: ToVppPrefix(&r.Src),
		DstPrefix: ToVppPrefix(&r.Dst),
		Proto:     ToVppIPProto(r.Proto),
	}
}

type ACL struct {
	ACLIndex uint32
	Tag      string
	Rules    []ACLRule
}
