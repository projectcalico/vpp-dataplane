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
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

type Rule struct {
	*types.Rule

	RuleID string
	VppID  uint32

	DstIPPortIPSetNames    []string
	DstNotIPPortIPSetNames []string
	SrcIPPortIPSetNames    []string
	SrcNotIPPortIPSetNames []string

	DstIPSetNames    []string
	DstNotIPSetNames []string
	SrcIPSetNames    []string
	SrcNotIPSetNames []string

	DstIPPortSetNames []string

	Annotations map[string]string
}

func (r *Rule) DeepCopy() *Rule {
	rule := &Rule{
		Rule: r.Rule.DeepCopy(),

		RuleID: r.RuleID,
		VppID:  r.VppID,

		DstIPPortIPSetNames:    make([]string, len(r.DstIPPortSetNames)),
		DstNotIPPortIPSetNames: make([]string, len(r.DstIPPortSetNames)),
		SrcIPPortIPSetNames:    make([]string, len(r.DstIPPortSetNames)),
		SrcNotIPPortIPSetNames: make([]string, len(r.DstIPPortSetNames)),
		DstIPSetNames:          make([]string, len(r.DstIPPortSetNames)),
		DstNotIPSetNames:       make([]string, len(r.DstIPPortSetNames)),
		SrcIPSetNames:          make([]string, len(r.DstIPPortSetNames)),
		SrcNotIPSetNames:       make([]string, len(r.DstIPPortSetNames)),
		DstIPPortSetNames:      make([]string, len(r.DstIPPortSetNames)),
	}

	copy(rule.DstIPPortIPSetNames, r.DstIPPortIPSetNames)
	copy(rule.DstNotIPPortIPSetNames, r.DstNotIPPortIPSetNames)
	copy(rule.SrcIPPortIPSetNames, r.SrcIPPortIPSetNames)
	copy(rule.SrcNotIPPortIPSetNames, r.SrcNotIPPortIPSetNames)
	copy(rule.DstIPSetNames, r.DstIPSetNames)
	copy(rule.DstNotIPSetNames, r.DstNotIPSetNames)
	copy(rule.SrcIPSetNames, r.SrcIPSetNames)
	copy(rule.SrcNotIPSetNames, r.SrcNotIPSetNames)
	copy(rule.DstIPPortSetNames, r.DstIPPortSetNames)

	return rule
}

func (r *Rule) String() string {
	s := fmt.Sprintf("[vpp-id=%d rid=%s", r.VppID, r.RuleID)

	s += types.StrListToString(" dipport==", r.DstIPPortIPSetNames)
	s += types.StrListToString(" dipport!=", r.DstNotIPPortIPSetNames)
	s += types.StrListToString(" sipport==", r.SrcIPPortIPSetNames)
	s += types.StrListToString(" sipport!=", r.SrcNotIPPortIPSetNames)

	s += types.StrListToString(" dipset==", r.DstIPSetNames)
	s += types.StrListToString(" dipset!=", r.DstNotIPSetNames)
	s += types.StrListToString(" sipset==", r.SrcIPSetNames)
	s += types.StrListToString(" sipset!=", r.SrcNotIPSetNames)

	s += types.StrListToString(" dipportset==", r.DstIPPortSetNames)

	s += "]"

	return s
}

func fromProtoRule(r *proto.Rule) (rule *Rule, err error) {
	rule = &Rule{
		Rule:   &types.Rule{},
		RuleID: r.RuleId,
		VppID:  types.InvalidID,
	}
	if r.GetMetadata() != nil {
		rule.Annotations = r.GetMetadata().GetAnnotations()
	}
	switch strings.ToLower(r.Action) {
	case "allow":
		rule.Action = types.ActionAllow
	case "deny":
		rule.Action = types.ActionDeny
	case "log":
		rule.Action = types.ActionLog
	case "pass":
		rule.Action = types.ActionPass
	default:
		return nil, fmt.Errorf("Unknown rule action: %s", r.Action)
	}

	switch r.IpVersion {
	case proto.IPVersion_ANY:
		rule.AddressFamily = types.FAMILY_ALL
	case proto.IPVersion_IPV4:
		rule.AddressFamily = types.FAMILY_V4
	case proto.IPVersion_IPV6:
		rule.AddressFamily = types.FAMILY_V6
	default:
		return nil, fmt.Errorf("Unknown rule AF: %d", r.IpVersion)
	}

	if r.Protocol != nil {
		if r.NotProtocol != nil {
			return nil, fmt.Errorf("Protocol and NotProtocol specified in Rule")
		}
		proto, err := parseProtocol(r.Protocol)
		if err != nil {
			return nil, err
		}
		rule.Filters = append(rule.Filters, types.RuleFilter{
			ShouldMatch: true,
			Type:        types.CapoFilterProto,
			Value:       int(proto),
		})
	}
	if r.NotProtocol != nil {
		proto, err := parseProtocol(r.NotProtocol)
		if err != nil {
			return nil, err
		}
		rule.Filters = append(rule.Filters, types.RuleFilter{
			ShouldMatch: false,
			Type:        types.CapoFilterProto,
			Value:       int(proto),
		})
	}

	// TODO: ICMP filters

	// Nets
	for _, str := range r.SrcNet {
		_, n, err := net.ParseCIDR(str)
		if err != nil {
			return nil, err
		}
		rule.SrcNet = append(rule.SrcNet, *n)
	}
	for _, str := range r.NotSrcNet {
		_, n, err := net.ParseCIDR(str)
		if err != nil {
			return nil, err
		}
		rule.SrcNotNet = append(rule.SrcNotNet, *n)
	}
	for _, str := range r.DstNet {
		_, n, err := net.ParseCIDR(str)
		if err != nil {
			return nil, err
		}
		rule.DstNet = append(rule.DstNet, *n)
	}
	for _, str := range r.NotDstNet {
		_, n, err := net.ParseCIDR(str)
		if err != nil {
			return nil, err
		}
		rule.DstNotNet = append(rule.DstNotNet, *n)
	}

	// Ports ranges
	for _, proto := range r.SrcPorts {
		rule.SrcPortRange = append(rule.SrcPortRange, types.PortRange{First: uint16(proto.First), Last: uint16(proto.Last)})
	}
	for _, proto := range r.NotSrcPorts {
		rule.SrcNotPortRange = append(rule.SrcNotPortRange, types.PortRange{First: uint16(proto.First), Last: uint16(proto.Last)})
	}
	for _, proto := range r.DstPorts {
		rule.DstPortRange = append(rule.DstPortRange, types.PortRange{First: uint16(proto.First), Last: uint16(proto.Last)})
	}
	for _, proto := range r.NotDstPorts {
		rule.DstNotPortRange = append(rule.DstNotPortRange, types.PortRange{First: uint16(proto.First), Last: uint16(proto.Last)})
	}

	// IPset references are stored ouside of the types.Rule since they may not yet exist in VPP
	// They are resolved when the rule is installed in VPP, at which point they are guaranteed to exist

	rule.DstIPPortIPSetNames = make([]string, len(r.DstNamedPortIpSetIds))
	copy(rule.DstIPPortIPSetNames, r.DstNamedPortIpSetIds)
	rule.DstNotIPPortIPSetNames = make([]string, len(r.NotDstNamedPortIpSetIds))
	copy(rule.DstNotIPPortIPSetNames, r.NotDstNamedPortIpSetIds)
	rule.SrcIPPortIPSetNames = make([]string, len(r.SrcNamedPortIpSetIds))
	copy(rule.SrcIPPortIPSetNames, r.SrcNamedPortIpSetIds)
	rule.SrcNotIPPortIPSetNames = make([]string, len(r.NotSrcNamedPortIpSetIds))
	copy(rule.SrcNotIPPortIPSetNames, r.NotSrcNamedPortIpSetIds)
	rule.DstIPSetNames = make([]string, len(r.DstIpSetIds))
	copy(rule.DstIPSetNames, r.DstIpSetIds)
	rule.DstNotIPSetNames = make([]string, len(r.NotDstIpSetIds))
	copy(rule.DstNotIPSetNames, r.NotDstIpSetIds)
	rule.SrcIPSetNames = make([]string, len(r.SrcIpSetIds))
	copy(rule.SrcIPSetNames, r.SrcIpSetIds)
	rule.SrcNotIPSetNames = make([]string, len(r.NotSrcIpSetIds))
	copy(rule.SrcNotIPSetNames, r.NotSrcIpSetIds)
	rule.DstIPPortSetNames = make([]string, len(r.DstIpPortSetIds))
	copy(rule.DstIPPortSetNames, r.DstIpPortSetIds)

	return rule, nil
}

func parseProtocol(pr *proto.Protocol) (types.IPProto, error) {
	switch u := pr.NumberOrName.(type) {
	case *proto.Protocol_Name:
		switch strings.ToLower(u.Name) {
		case "tcp":
			return types.TCP, nil
		case "udp":
			return types.UDP, nil
		case "icmp":
			return types.ICMP, nil
		case "icmp6":
			return types.ICMP6, nil
		case "sctp":
			return types.SCTP, nil
		case "udplite":
			return 136, nil // TODO fix?
		default:
			return 0, fmt.Errorf("unknown protocol: %s", u.Name)
		}
	case *proto.Protocol_Number:
		return types.IPProto(u.Number), nil
	default:
		return 0, fmt.Errorf("cannot parse protocol")
	}
}

func (r *Rule) Create(vpp *vpplink.VppLink, state *PolicyState) (err error) {
	// Resolve ipset IDs from names
	// TODO maybe refactor? :p
	r.DstIPPortIPSet = nil
	r.DstNotIPPortIPSet = nil
	r.SrcIPPortIPSet = nil
	r.SrcNotIPPortIPSet = nil
	r.DstIPSet = nil
	r.DstNotIPSet = nil
	r.SrcIPSet = nil
	r.SrcNotIPSet = nil
	r.DstIPPortSet = nil

	for _, n := range r.DstIPPortIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.DstIPPortIPSet = append(r.DstIPPortIPSet, ipset.VppID)
	}
	for _, n := range r.DstNotIPPortIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.DstNotIPPortIPSet = append(r.DstNotIPPortIPSet, ipset.VppID)
	}
	for _, n := range r.SrcIPPortIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.SrcIPPortIPSet = append(r.SrcIPPortIPSet, ipset.VppID)
	}
	for _, n := range r.SrcNotIPPortIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.SrcNotIPPortIPSet = append(r.SrcNotIPPortIPSet, ipset.VppID)
	}
	for _, n := range r.DstIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.DstIPSet = append(r.DstIPSet, ipset.VppID)
	}
	for _, n := range r.DstNotIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.DstNotIPSet = append(r.DstNotIPSet, ipset.VppID)
	}
	for _, n := range r.SrcIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.SrcIPSet = append(r.SrcIPSet, ipset.VppID)
	}
	for _, n := range r.SrcNotIPSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.SrcNotIPSet = append(r.SrcNotIPSet, ipset.VppID)
	}
	for _, n := range r.DstIPPortSetNames {
		ipset, ok := state.IPSets[n]
		if !ok || ipset.VppID == types.InvalidID {
			return fmt.Errorf("ipset not found (%v) or created (%d) for rule", ok, ipset.VppID)
		}
		r.DstIPPortSet = append(r.DstIPPortSet, ipset.VppID)
	}

	id, err := vpp.RuleCreate(r.Rule)
	if err != nil {
		return errors.Wrap(err, "error creating rule")
	}
	r.VppID = id
	logrus.Infof("policy(add) VPP rule=%s id=%d", r.Rule, id)
	return nil
}

func (r *Rule) Delete(vpp *vpplink.VppLink) (err error) {
	logrus.Infof("policy(del) VPP rule id=%d", r.VppID)
	err = vpp.RuleDelete(r.VppID)
	if err != nil {
		return err
	}
	r.VppID = types.InvalidID
	return nil
}
