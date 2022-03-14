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
	"fmt"
	"net"
	"reflect"

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

func (i IpsetType) String() string {
	switch i {
	case IpsetTypeIP:
		return "ip"
	case IpsetTypeIPPort:
		return "ipport"
	case IpsetTypeNet:
		return "net"
	}
	return "ipset-unknown"
}

type IPPort struct {
	Addr    net.IP
	L4Proto uint8
	Port    uint16
}

type RuleAction uint8

const (
	ActionAllow RuleAction = RuleAction(capo.CAPO_ALLOW)
	ActionDeny  RuleAction = RuleAction(capo.CAPO_DENY)
	ActionLog   RuleAction = RuleAction(capo.CAPO_LOG)
	ActionPass  RuleAction = RuleAction(capo.CAPO_PASS)
)

func (r RuleAction) String() string {
	switch r {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionLog:
		return "log"
	case ActionPass:
		return "pass"
	}
	return "action-unknown"
}

type PortRange struct {
	First uint16
	Last  uint16
}

func (pr PortRange) String() string {
	if pr.First == pr.Last {
		return fmt.Sprintf("%d", pr.First)
	} else {
		return fmt.Sprintf("%d-%d", pr.First, pr.Last)
	}
}

type CapoFilterType uint8

const (
	CapoFilterTypeNone CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_NONE_TYPE)
	CapoFilterICMPType CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_ICMP_TYPE)
	CapoFilterICMPCode CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_ICMP_CODE)
	CapoFilterProto    CapoFilterType = CapoFilterType(capo.CAPO_RULE_FILTER_L4_PROTO)
)

func (ft CapoFilterType) String() string {
	switch ft {
	case CapoFilterTypeNone:
		return "none"
	case CapoFilterICMPType:
		return "icmp-type"
	case CapoFilterICMPCode:
		return "icmp-code"
	case CapoFilterProto:
		return "proto"
	}
	return "unknown-filter-type"
}

type RuleFilter struct {
	ShouldMatch bool
	Type        CapoFilterType
	Value       int
}

func (f RuleFilter) String() string {
	if f.ShouldMatch {
		return fmt.Sprintf("%s==%d", f.Type.String(), f.Value)
	} else {
		return fmt.Sprintf("%s!=%d", f.Type.String(), f.Value)
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

	DstIPPortSet []uint32
}

func StrableListToString(prefix string, arg interface{}) string {
	value := reflect.ValueOf(arg)
	if value.Len() == 0 {
		return ""
	}
	s := fmt.Sprintf("%s[", prefix)
	for i := 0; i < value.Len(); i++ {
		if i > 0 {
			s += ","
		}
		v := reflect.Indirect(value.Index(i))
		m := v.MethodByName("String")
		if !m.IsValid() {
			m = v.Addr().MethodByName("String")
		}
		ret := m.Call(make([]reflect.Value, 0))[0]
		s += ret.Interface().(string)
	}
	return s + "]"
}

func StrListToString(prefix string, lst []string) string {
	if len(lst) == 0 {
		return ""
	}
	s := fmt.Sprintf("%s[", prefix)
	for i, elem := range lst {
		if i > 0 {
			s += ","
		}
		s = fmt.Sprintf("%s%s", s, elem)
	}
	return s + "]"
}

func IntListToString(prefix string, lst []uint32) string {
	if len(lst) == 0 {
		return ""
	}
	s := fmt.Sprintf("%s[", prefix)
	for i, elem := range lst {
		if i > 0 {
			s += ","
		}
		s = fmt.Sprintf("%s%d", s, elem)
	}
	return s + "]"
}

func (r *Rule) String() string {
	s := fmt.Sprintf("action=%s", r.Action.String())
	s += StrableListToString("filters=", r.Filters)

	s += StrableListToString(" dst==", r.DstNet)
	s += StrableListToString(" dst!=", r.DstNotNet)
	s += StrableListToString(" src==", r.SrcNet)
	s += StrableListToString(" src!=", r.SrcNotNet)

	s += StrableListToString(" dport==", r.DstPortRange)
	s += StrableListToString(" dport!=", r.DstNotPortRange)
	s += StrableListToString(" sport==", r.SrcPortRange)
	s += StrableListToString(" sport!=", r.SrcNotPortRange)

	s += IntListToString(" dipport==", r.DstIPPortIPSet)
	s += IntListToString(" dipport!=", r.DstNotIPPortIPSet)
	s += IntListToString(" sipport==", r.SrcIPPortIPSet)
	s += IntListToString(" sipport!=", r.SrcNotIPPortIPSet)

	s += IntListToString(" dipport2==", r.DstIPPortSet)

	s += IntListToString(" dipset==", r.DstIPSet)
	s += IntListToString(" dipset!=", r.DstNotIPSet)
	s += IntListToString(" sipset==", r.SrcIPSet)
	s += IntListToString(" sipset!=", r.SrcNotIPSet)

	return s
}

type Policy struct {
	InboundRuleIDs  []uint32
	OutboundRuleIDs []uint32
}

func (p *Policy) String() string {
	s := "["
	if len(p.InboundRuleIDs) > 0 {
		s += " inRuleIDs=["
		for i, ruleID := range p.InboundRuleIDs {
			if i > 0 {
				s += ","
			}
			s = fmt.Sprintf("%s%d", s, ruleID)
		}
		s += "]"
	}
	if len(p.OutboundRuleIDs) > 0 {
		s += " outRuleIDs=["
		for i, ruleID := range p.OutboundRuleIDs {
			if i > 0 {
				s += ","
			}
			s = fmt.Sprintf("%s%d", s, ruleID)
		}
		s += "]"
	}
	s += "]"
	return s
}

type InterfaceConfig struct {
	IngressPolicyIDs []uint32
	EgressPolicyIDs  []uint32
	ProfileIDs       []uint32
}

func NewInterfaceConfig() *InterfaceConfig {
	return &InterfaceConfig{
		IngressPolicyIDs: make([]uint32, 0),
		EgressPolicyIDs:  make([]uint32, 0),
		ProfileIDs:       make([]uint32, 0),
	}
}

func toCapoFilter(f *RuleFilter) capo.CapoRuleFilter {
	return capo.CapoRuleFilter{
		Value:       uint32(f.Value),
		Type:        capo.CapoRuleFilterType(f.Type),
		ShouldMatch: boolToU8(f.ShouldMatch),
	}
}

func boolToU8(v bool) uint8 {
	if v {
		return uint8(1)
	}
	return uint8(0)
}

func (i *IPPort) Equal(j *IPPort) bool {
	return i.Port == j.Port && i.L4Proto == j.L4Proto && i.Addr.Equal(j.Addr)
}

func toCapoPortRange(pr PortRange) capo.CapoPortRange {
	return capo.CapoPortRange{
		Start: pr.First,
		End:   pr.Last,
	}
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
	for _, id := range r.DstIPPortSet {
		entry := capo.CapoRuleEntry{IsSrc: false, IsNot: false, Type: capo.CAPO_PORT_IP_SET}
		entry.Data.SetSetID(capo.CapoEntrySetID{SetID: id})
		cr.Matches = append(cr.Matches, entry)
	}
	return cr
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
