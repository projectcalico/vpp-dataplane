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

package types

import (
	"net"

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/capo"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
)

const InvalidID uint32 = ^uint32(0)

type IpsetType uint8

const (
	IpsetTypeIP     IpsetType = IpsetType(capo.CAPO_IP)
	IpsetTypeIPPort IpsetType = IpsetType(capo.CAPO_IP_AND_PORT)
	IpsetTypeNet    IpsetType = IpsetType(capo.CAPO_NET)
)

type IPPort struct {
	Addr    net.IP
	L4Proto uint8
	Port    uint16
}

func (i *IPPort) Equal(j *IPPort) bool {
	return i.Port == j.Port && i.L4Proto == j.L4Proto && i.Addr.Equal(j.Addr)
}

type RuleAction uint8

const (
	ActionAllow RuleAction = RuleAction(capo.CAPO_ALLOW)
	ActionDeny  RuleAction = RuleAction(capo.CAPO_DENY)
	ActionLog   RuleAction = RuleAction(capo.CAPO_LOG)
	ActionPass  RuleAction = RuleAction(capo.CAPO_PASS)
)

type PortRange struct {
	First uint16
	Last  uint16
}

func toCapoPortRange(pr PortRange) capo.CapoPortRange {
	return capo.CapoPortRange{
		Start: pr.First,
		End:   pr.Last,
	}
}

type CapoFilterType uint8

const (
	CapoFilterTypeNone CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_NONE_TYPE)
	CapoFilterICMPType CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_ICMP_TYPE)
	CapoFilterICMPCode CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_ICMP_CODE)
	CapoFilterProto    CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_L4_PROTO)
)

type RuleFilter struct {
	ShouldMatch bool
	Type        CapoFilterType
	Value       int
}

func toCapoFilter(f *RuleFilter) capo.CapoRuleFilter {
	return capo.CapoRuleFilter{
		Value:       uint32(f.Value),
		Type:        capo.CapoRuleFilterType(f.Type),
		ShouldMatch: boolToU8(f.ShouldMatch),
	}
}

type Rule struct {
	Action        RuleAction
	AddressFamily int
	Filters       []RuleFilter

	DstNet    []net.IPNet
	DstNotNet []net.IPNet
	SrcNet    []net.IPNet
	SrcNotNet []net.IPNet

	DstPortRange    []PortRange
	DstNotPortRange []PortRange
	SrcPortRange    []PortRange
	SrcNotPortRange []PortRange

	DstIPPortIPSet    []uint32
	DstNotIPPortIPSet []uint32
	SrcIPPortIPSet    []uint32
	SrcNotIPPortIPSet []uint32

	DstIPSet    []uint32
	DstNotIPSet []uint32
	SrcIPSet    []uint32
	SrcNotIPSet []uint32
}

func boolToU8(v bool) uint8 {
	if v {
		return uint8(1)
	}
	return uint8(0)
}

func ToCapoRule(r *Rule) (cr capo.CapoRule) {
	var filters [3]capo.CapoRuleFilter
	for i, f := range r.Filters {
		if i == 3 {
			break
		}
		filters[i] = toCapoFilter(&f)
	}

	cr = capo.CapoRule{
		Action: capo.CapoRuleAction(r.Action),
		Af:     ip_types.AddressFamily(r.AddressFamily),

		Filters: filters,
	}

	for _, n := range r.DstNet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: false, Type: capo.CAPO_CIDR}
		entry.Data.SetCidr(ToVppPrefix(&n))
		cr.Matches = append(cr.Matches, entry)
	}
	for _, n := range r.DstNotNet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: true, Type: capo.CAPO_CIDR}
		entry.Data.SetCidr(ToVppPrefix(&n))
		cr.Matches = append(cr.Matches, entry)
	}
	for _, n := range r.SrcNet {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: false, Type: capo.CAPO_CIDR}
		entry.Data.SetCidr(ToVppPrefix(&n))
		cr.Matches = append(cr.Matches, entry)
	}
	for _, n := range r.SrcNotNet {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: true, Type: capo.CAPO_CIDR}
		entry.Data.SetCidr(ToVppPrefix(&n))
		cr.Matches = append(cr.Matches, entry)
	}

	for _, pr := range r.DstPortRange {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: false, Type: capo.CAPO_PORT_RANGE}
		entry.Data.SetPortRange(toCapoPortRange(pr))
		cr.Matches = append(cr.Matches, entry)
	}
	for _, pr := range r.DstNotPortRange {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: true, Type: capo.CAPO_PORT_RANGE}
		entry.Data.SetPortRange(toCapoPortRange(pr))
		cr.Matches = append(cr.Matches, entry)
	}
	for _, pr := range r.SrcPortRange {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: false, Type: capo.CAPO_PORT_RANGE}
		entry.Data.SetPortRange(toCapoPortRange(pr))
		cr.Matches = append(cr.Matches, entry)
	}
	for _, pr := range r.SrcNotPortRange {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: true, Type: capo.CAPO_PORT_RANGE}
		entry.Data.SetPortRange(toCapoPortRange(pr))
		cr.Matches = append(cr.Matches, entry)
	}

	for _, id := range r.DstIPPortIPSet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: false, Type: capo.CAPO_PORT_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	for _, id := range r.DstNotIPPortIPSet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: true, Type: capo.CAPO_PORT_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	for _, id := range r.SrcIPPortIPSet {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: false, Type: capo.CAPO_PORT_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	for _, id := range r.SrcNotIPPortIPSet {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: true, Type: capo.CAPO_PORT_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}

	for _, id := range r.DstIPSet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: false, Type: capo.CAPO_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	for _, id := range r.DstNotIPSet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: true, Type: capo.CAPO_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	for _, id := range r.SrcIPSet {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: false, Type: capo.CAPO_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	for _, id := range r.SrcNotIPSet {
		entry := capo.CapoRuleEntry{IsSrc: true, IsNot: true, Type: capo.CAPO_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	return cr
}

type Policy struct {
	InboundRuleIDs  []uint32
	OutboundRuleIDs []uint32
}

func ToCapoPolicy(p *Policy) (items []capo.CapoPolicyItem) {
	items = make([]capo.CapoPolicyItem, 0, len(p.InboundRuleIDs)+len(p.OutboundRuleIDs))
	for _, rid := range p.InboundRuleIDs {
		items = append(items, capo.CapoPolicyItem{
			IsInbound: true,
			RuleID:    rid,
		})
	}
	for _, rid := range p.OutboundRuleIDs {
		items = append(items, capo.CapoPolicyItem{
			IsInbound: false,
			RuleID:    rid,
		})
	}
	return items
}
