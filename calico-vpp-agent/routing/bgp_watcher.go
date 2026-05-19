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

package routing

import (
	"context"
	"fmt"
	"net"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/tomb.v2"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"

	// needed for GoBGP building (in ../Makefile, gobgp target)
	_ "github.com/inconshreveable/mousetrap"
	_ "github.com/spf13/cobra"
)

func (s *Server) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := attr.UnmarshalTo(nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := attr.UnmarshalTo(mpReachAttr); err == nil {
			if len(mpReachAttr.NextHops) != 1 {
				s.log.Fatalf("Cannot process more than one Nlri in path attributes: %+v", mpReachAttr)
			}
			return mpReachAttr.NextHops[0]
		}
	}
	return ""
}

// injectRoute is a helper function to inject BGP routes to VPP
// TODO: multipath support
func (s *Server) injectRoute(path *bgpapi.Path) error {
	var dst net.IPNet
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	labeledVPNIPAddressPrefixNlri := &bgpapi.LabeledVPNIPAddressPrefix{}
	vpn := false
	otherNodeIP := net.ParseIP(s.getNexthop(path))
	if otherNodeIP == nil {
		return fmt.Errorf("cannot determine path nexthop: %+v", path)
	}

	if err := path.Nlri.UnmarshalTo(ipAddrPrefixNlri); err == nil {
		dst.IP = net.ParseIP(ipAddrPrefixNlri.Prefix)
		if dst.IP == nil {
			return fmt.Errorf("cannot parse nlri addr: %s", ipAddrPrefixNlri.Prefix)
		} else if dst.IP.To4() == nil {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 128)
		} else {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 32)
		}
	} else {
		err := path.Nlri.UnmarshalTo(labeledVPNIPAddressPrefixNlri)
		if err == nil {
			dst.IP = net.ParseIP(labeledVPNIPAddressPrefixNlri.Prefix)
			if dst.IP == nil {
				return fmt.Errorf("cannot parse nlri addr: %s", labeledVPNIPAddressPrefixNlri.Prefix)
			} else if dst.IP.To4() == nil {
				dst.Mask = net.CIDRMask(int(labeledVPNIPAddressPrefixNlri.PrefixLen), 128)
			} else {
				dst.Mask = net.CIDRMask(int(labeledVPNIPAddressPrefixNlri.PrefixLen), 32)
			}
			vpn = true
		} else {
			// Fallback: handle SRPolicyNLRI that may not have been caught by the SAFI check
			srnrli := &bgpapi.SRPolicyNLRI{}
			if err := path.Nlri.UnmarshalTo(srnrli); err == nil {
				s.log.Debugf("injectRoute: SRPolicyNLRI fallback, redirecting to injectSRv6Policy")
				return s.injectSRv6Policy(path)
			}
			return fmt.Errorf("cannot handle Nlri: %+v", path.Nlri)
		}
	}

	cn := &common.NodeConnectivity{
		Dst:     dst,
		NextHop: otherNodeIP,
	}
	if vpn {
		rd := &bgpapi.RouteDistinguisherTwoOctetASN{}
		err := labeledVPNIPAddressPrefixNlri.Rd.UnmarshalTo(rd)
		if err != nil {
			return errors.Wrap(err, "Error Unmarshalling labeledVPNIPAddressPrefixNlri.Rd")
		}
		cn.Vni = rd.Assigned
	}
	if path.IsWithdraw {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.ConnectivityDeleted,
			Old:  cn,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.ConnectivityAdded,
			New:  cn,
		})
	}
	return nil
}

// vppMaxSRv6Sids is the fixed size of vl_api_srv6_sid_list_t.sids in VPP
// (src/vnet/srv6/sr.api). Each VPP Segment List therefore holds at most 16
// SIDs; multiple Segment Lists must be installed via SrPolicyMod.
const vppMaxSRv6Sids = 16

// errSRPolicyMixedBehavior is wrapped into the error returned by
// getSRPolicy when an advertised SR Policy's Segment Lists disagree on
// trailing endpoint behavior. injectSRv6Policy unwraps it to decide
// whether to dispatch an SRv6PolicyDeleted event for the endpoint --
// previously-installed state under the same NLRI key must be torn down,
// not silently kept, when the controller's new advertisement is rejected.
var errSRPolicyMixedBehavior = errors.New("sr policy: candidate paths disagree on endpoint behavior; this agent installs one Behavior per BSID and cannot represent the candidate-path set safely")

// walkSRPolicyInnerTLVs invokes fn for every inner TLV inside the
// TunnelEncapAttribute(s) of an SR Policy path, hiding the
// Path -> Pattrs -> TunnelEncapAttribute.Tlvs -> Tlv.Tlvs unmarshal nest.
func walkSRPolicyInnerTLVs(path *bgpapi.Path, fn func(*anypb.Any) error) error {
	for _, pattr := range path.Pattrs {
		tun := &bgpapi.TunnelEncapAttribute{}
		if err := pattr.UnmarshalTo(tun); err != nil {
			// path.Pattrs is heterogeneous (OriginAttribute,
			// AsPathAttribute, NextHopAttribute, ...). Anything that is
			// not a TunnelEncapAttribute fails UnmarshalTo here, which is
			// expected, not a decoding bug -- skip and keep scanning.
			continue
		}
		for _, tlv := range tun.Tlvs {
			for _, innerTlv := range tlv.Tlvs {
				if err := fn(innerTlv); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// parseSegmentList converts one TunnelEncapSubTLVSRSegmentList into a
// single types.Srv6SidList, preserving the sub-TLV's weight. It also
// returns the last SegmentTypeB so the caller can inspect the
// EndpointBehaviorStructure that drives the SR Policy install behavior.
//
// Caller contract: getSRPolicy propagates any error returned here through
// walkSRPolicyInnerTLVs, which means *one bad Segment List rejects the
// entire SR Policy*, not just the offending list. That whole-policy
// rejection is intentional -- partial installation would change the
// candidate-path / weight semantics the controller advertised (see the
// design note in the PR description). parseSegmentList itself does not
// know about sibling Segment Lists; it just guarantees that a list it
// accepts can be installed in VPP without further validation.
//
// Segment-type policy: an SR Policy advertised to an SRv6 dataplane is
// expected to carry SegmentTypeB (IPv6 SID) entries end-to-end. A
// SegmentTypeA (SR-MPLS label) entry is legitimate per
// draft-ietf-idr-segment-routing-te-policy but cannot be installed by
// this SRv6 agent; silently skipping it would install a SID chain that
// differs from the advertised one -- the forwarding path would change
// in a way the advertising peer never intended. The list is therefore
// rejected with a distinct error so operators can tell "advertiser sent
// SR-MPLS segments we cannot install" from "advertiser sent malformed
// protobuf bytes".
//
// EndpointBehaviorStructure on the trailing SegmentTypeB is required
// (it drives srv6tunnel.Behavior). Lists whose last segment has no
// behavior structure are rejected here per-list, so getSRPolicy does
// not have to re-validate it after the walk.
func parseSegmentList(
	sub *bgpapi.TunnelEncapSubTLVSRSegmentList,
	srnrli *bgpapi.SRPolicyNLRI,
) (types.Srv6SidList, *bgpapi.SegmentTypeB, error) {
	segments := make([]*bgpapi.SegmentTypeB, 0, len(sub.GetSegments()))
	for i, raw := range sub.GetSegments() {
		segment := &bgpapi.SegmentTypeB{}
		if err := raw.UnmarshalTo(segment); err == nil {
			segments = append(segments, segment)
			continue
		}
		// Distinguish "advertiser sent a known but unsupported segment
		// type (SR-MPLS Type-A)" from "advertiser sent bytes that decode
		// as no SR segment type at all". Both reject the list, but the
		// SR-MPLS case is intentional on the advertiser's side and the
		// genuinely-malformed case is a protocol violation; the
		// different error wording makes the operator-side triage
		// obvious.
		typeA := &bgpapi.SegmentTypeA{}
		if err := raw.UnmarshalTo(typeA); err == nil {
			return types.Srv6SidList{}, nil, fmt.Errorf(
				"sr policy endpoint=%s: SegmentTypeA (SR-MPLS label %d) at index %d cannot be installed by this SRv6 agent; rejecting list to avoid installing a SID chain different from the advertised one",
				net.IP(srnrli.Endpoint), typeA.GetLabel(), i)
		}
		return types.Srv6SidList{}, nil, fmt.Errorf(
			"sr policy endpoint=%s has an unsupported or malformed segment at index %d",
			net.IP(srnrli.Endpoint), i)
	}
	// Defensive: protobuf message with zero `segments` repeated entries.
	// parseSegmentList is called via walkSRPolicyInnerTLVs which only
	// hits us for actual SegmentList sub-TLVs, but the peer could still
	// advertise one with no inner Any entries.
	if len(segments) == 0 {
		return types.Srv6SidList{}, nil, fmt.Errorf(
			"sr policy endpoint=%s has a segment list with no segments",
			net.IP(srnrli.Endpoint))
	}
	if len(segments) > vppMaxSRv6Sids {
		return types.Srv6SidList{}, nil, fmt.Errorf(
			"sr policy endpoint=%s segment list has %d segments, vpp supports up to %d",
			net.IP(srnrli.Endpoint), len(segments), vppMaxSRv6Sids)
	}
	// EndpointBehaviorStructure is optional in the protobuf but required
	// by this agent: srv6tunnel.Behavior is derived from the trailing
	// segment's behavior code, and the generated GetEndpointBehaviorStructure()
	// is nil-safe but accessing .Behavior on the returned nil pointer panics.
	// Reject the list here instead of crashing later in getSRPolicy.
	last := segments[len(segments)-1]
	if last.GetEndpointBehaviorStructure() == nil {
		return types.Srv6SidList{}, nil, fmt.Errorf(
			"sr policy endpoint=%s last segment has no endpoint behavior structure",
			net.IP(srnrli.Endpoint))
	}
	sids := [vppMaxSRv6Sids]ip_types.IP6Address{}
	for i, segment := range segments {
		sids[i] = types.ToVppIP6Address(net.IP(segment.Sid))
	}
	weight := uint32(1)
	if w := sub.GetWeight(); w != nil {
		weight = w.GetWeight()
	}
	return types.Srv6SidList{
		NumSids: uint8(len(segments)),
		Weight:  weight,
		Sids:    sids,
	}, last, nil
}

func (s *Server) getSRPolicy(path *bgpapi.Path) (srv6Policy *types.SrPolicy, srv6tunnel *common.SRv6Tunnel, srnrli *bgpapi.SRPolicyNLRI, err error) {
	srnrli = &bgpapi.SRPolicyNLRI{}
	srv6bsid := &bgpapi.SRBindingSID{}
	srv6tunnel = &common.SRv6Tunnel{}

	if err := path.Nlri.UnmarshalTo(srnrli); err != nil {
		return nil, nil, nil, err
	}
	srv6tunnel.Dst = net.IP(srnrli.Endpoint)

	// SR Policy withdraws carry only the (distinguisher, color, endpoint)
	// NLRI key; per RFC 9012 / draft-ietf-idr-segment-routing-te-policy the
	// TunnelEncap path attribute is not required. Short-circuit so the
	// caller (injectSRv6Policy) can dispatch SRv6PolicyDeleted instead of
	// reaching the empty-segments check below and dropping the withdraw
	// without emitting SRv6PolicyDeleted.
	if path.IsWithdraw {
		return nil, srv6tunnel, srnrli, nil
	}

	var (
		sidLists      []types.Srv6SidList
		listBehaviors []bgpapi.SRv6Behavior // parallel to sidLists; trailing-segment Behavior per list
	)

	err = walkSRPolicyInnerTLVs(path, func(innerTlv *anypb.Any) error {
		// Segment List sub-TLV: one VPP Srv6SidList per occurrence so the
		// SR Policy Architecture (RFC 9256) notion of independent Segment
		// Lists -- weighted load balancing or back-up candidates -- is
		// preserved end-to-end instead of being flattened into a single
		// strict SID chain.
		sub := &bgpapi.TunnelEncapSubTLVSRSegmentList{}
		if e := innerTlv.UnmarshalTo(sub); e == nil {
			list, last, lerr := parseSegmentList(sub, srnrli)
			if lerr != nil {
				return lerr
			}
			sidLists = append(sidLists, list)
			listBehaviors = append(listBehaviors, last.GetEndpointBehaviorStructure().GetBehavior())
			return nil
		}
		// Binding SID sub-TLV.
		bsid := &bgpapi.TunnelEncapSubTLVSRBindingSID{}
		if e := innerTlv.UnmarshalTo(bsid); e == nil {
			s.log.Debugf("getSRPolicy TunnelEncapSubTLVSRBindingSID")
			if bsid.Bsid != nil {
				return bsid.Bsid.UnmarshalTo(srv6bsid)
			}
			return nil
		}
		// Priority sub-TLV.
		prio := &bgpapi.TunnelEncapSubTLVSRPriority{}
		if e := innerTlv.UnmarshalTo(prio); e == nil {
			s.log.Debugf("getSRPolicyPriority TunnelEncapSubTLVSRPriority")
			srv6tunnel.Priority = prio.Priority
		}
		return nil
	})
	if err != nil {
		return nil, nil, srnrli, err
	}
	if len(sidLists) == 0 {
		return nil, nil, srnrli, fmt.Errorf(
			"sr policy endpoint=%s has no segments", net.IP(srnrli.Endpoint))
	}

	srv6Policy = &types.SrPolicy{
		Bsid:     types.ToVppIP6Address(net.IP(srv6bsid.Sid)),
		IsSpray:  false,
		IsEncap:  true,
		FibTable: 0,
		SidLists: sidLists,
	}
	srv6tunnel.Bsid = srv6Policy.Bsid.ToIP()
	srv6tunnel.Policy = srv6Policy

	// RFC 9256 permits candidate paths to terminate with different endpoint
	// behaviors, but this agent's install layer keeps one Behavior per BSID
	// (srv6tunnel.Behavior is matched against the destination pod prefix
	// family in connectivity/srv6.go: getPolicyNode), and VPP installs all
	// Segment Lists under a single sr_policy entry that ECMP/weight-load-
	// balances across them. Accepting a mixed-behavior policy would mean
	// installing two SID chains with one decap behavior, and traffic that
	// hashes onto a list whose trailing segment expects the other behavior
	// would be dropped/misdecapped at the egress node. Reject the policy
	// here so the failure is visible at receive time instead of becoming a
	// silent forwarding bug. parseSegmentList already guarantees every
	// trailing segment has a non-nil EndpointBehaviorStructure.
	for i := 1; i < len(listBehaviors); i++ {
		if listBehaviors[i] != listBehaviors[0] {
			return nil, nil, srnrli, fmt.Errorf(
				"sr policy endpoint=%s: segment list 0 ends with endpoint behavior %d, segment list %d ends with %d: %w",
				net.IP(srnrli.Endpoint), listBehaviors[0], i, listBehaviors[i], errSRPolicyMixedBehavior)
		}
	}
	srv6tunnel.Behavior = uint8(listBehaviors[0])

	return srv6Policy, srv6tunnel, srnrli, nil
}

func (s *Server) injectSRv6Policy(path *bgpapi.Path) error {
	s.log.Debugf("injectSRv6Policy called")
	_, srv6tunnel, srnrli, err := s.getSRPolicy(path)

	if err != nil {
		// The rejected advertisement may be an UPDATE for an SR Policy that
		// was previously accepted and installed in VPP. Keeping the old
		// installed state would diverge from the controller's view (the
		// controller considers the policy replaced; we silently keep the old
		// version). For rejection paths that hit on a parseable NLRI, treat
		// the receive-time failure as an implicit withdraw of any earlier
		// install under the same endpoint by dispatching SRv6PolicyDeleted.
		// SRv6Provider.DelConnectivity is currently a no-op (separate
		// pre-existing FIXME) so the actual VPP teardown will land when
		// that work merges; the event signal here makes the cleanup intent
		// correct in the meantime instead of leaving a silent gap.
		//
		// Scoped to errSRPolicyMixedBehavior for now: only this reject
		// path is reachable AFTER an initial accept (the receive-time
		// validation paths in parseSegmentList / NLRI unmarshal would
		// have rejected the first advertisement too, so there is no
		// stale install to tear down).
		if srnrli != nil && srnrli.Endpoint != nil && errors.Is(err, errSRPolicyMixedBehavior) {
			s.log.Warnf("injectSRv6Policy: rejecting mixed-behavior SR Policy for endpoint=%s and signalling teardown of any prior install under the same endpoint", net.IP(srnrli.Endpoint))
			common.SendEvent(common.CalicoVppEvent{
				Type: common.SRv6PolicyDeleted,
				Old: &common.NodeConnectivity{
					Dst:              net.IPNet{},
					NextHop:          srnrli.Endpoint,
					ResolvedProvider: "",
					Custom:           &common.SRv6Tunnel{Dst: net.IP(srnrli.Endpoint)},
				},
			})
		}
		return errors.Wrap(err, "error injectSRv6Policy")
	}
	s.log.Debugf("injectSRv6Policy: endpoint=%s, dst=%s, behavior=%d, bsid=%s, sids=%v",
		net.IP(srnrli.Endpoint), srv6tunnel.Dst, srv6tunnel.Behavior, srv6tunnel.Bsid, srv6tunnel.Sid)

	cn := &common.NodeConnectivity{
		Dst:              net.IPNet{},
		NextHop:          srnrli.Endpoint,
		ResolvedProvider: "",
		Custom:           srv6tunnel,
	}
	if path.IsWithdraw {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.SRv6PolicyDeleted,
			Old:  cn,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.SRv6PolicyAdded,
			New:  cn,
		})
	}
	return nil
}

func (s *Server) startBGPMonitoring() (func(), error) {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	ctx, stopFunc := context.WithCancel(context.Background())
	err := s.BGPServer.WatchEvent(ctx,
		&bgpapi.WatchEventRequest{
			Table: &bgpapi.WatchEventRequest_Table{
				Filters: []*bgpapi.WatchEventRequest_Table_Filter{{
					Type: bgpapi.WatchEventRequest_Table_Filter_BEST,
				}},
			},
		},
		func(r *bgpapi.WatchEventResponse) {
			if table := r.GetTable(); table != nil {
				for _, path := range table.GetPaths() {
					if path == nil || path.GetFamily() == nil {
						s.log.Warnf("nil path update, skipping")
						continue
					}
					if nodeIP4 == nil && path.GetFamily().Afi == bgpapi.Family_AFI_IP {
						s.log.Debugf("Ignoring ipv4 path with no node ip4")
						continue
					}
					if nodeIP6 == nil && path.GetFamily().Afi == bgpapi.Family_AFI_IP6 {
						s.log.Debugf("Ignoring ipv6 path with no node ip6")
						continue
					}
					if path.GetNeighborIp() == "<nil>" || path.GetNeighborIp() == "" { // Weird GoBGP API behaviour
						s.log.Debugf("Ignoring internal path")
						continue
					}
					if *config.GetCalicoVppFeatureGates().SRv6Enabled && path.GetFamily().GetSafi() == bgpapi.Family_SAFI_SR_POLICY {
						s.log.Debugf("Path SRv6")
						err := s.injectSRv6Policy(path)
						if err != nil {
							s.log.Errorf("cannot inject SRv6: %v", err)
						}
						continue
					}
					s.log.Infof("Got path update from=%s as=%d family=%s", path.GetSourceId(), path.GetSourceAsn(), path.GetFamily())
					err := s.injectRoute(path)
					if err != nil {
						s.log.Errorf("cannot inject route: %v", err)
					}
				}
			}
		},
	)
	return stopFunc, err
}

func (s *Server) NewBGPPolicyV4V6(CIDR string, matchOperator calicov3.BGPFilterMatchOperator, action calicov3.BGPFilterAction) (*bgpapi.DefinedSet, bgpapi.MatchSet_Type, bgpapi.RouteAction, string, error) {
	routeAction := bgpapi.RouteAction_ACCEPT
	if action == calicov3.Reject {
		routeAction = bgpapi.RouteAction_REJECT
	} else if action != calicov3.Accept {
		return nil, 0, 0, "", errors.Errorf("error creating new bgp policy: action %s not supported", action)
	}

	var matchSetType bgpapi.MatchSet_Type
	var minMask, maxMask uint32
	if matchOperator == calicov3.MatchOperatorIn || matchOperator == calicov3.MatchOperatorNotIn {
		_, subnet, err := net.ParseCIDR(CIDR)
		if err != nil {
			return nil, 0, 0, "", errors.Wrap(err, "error creating new bgp policy")
		}
		ones, bits := subnet.Mask.Size()
		minMask = uint32(ones)
		maxMask = uint32(bits)
		if matchOperator == calicov3.MatchOperatorIn {
			matchSetType = bgpapi.MatchSet_ANY // any and all are same in our case as we have only one member of the defined set
		} else {
			matchSetType = bgpapi.MatchSet_INVERT
		}
	} else {
		// mask is zero
		if matchOperator == calicov3.MatchOperatorEqual {
			matchSetType = bgpapi.MatchSet_ANY
		} else {
			matchSetType = bgpapi.MatchSet_INVERT
		}
	}

	prefixName := CIDR + "prefix" + fmt.Sprint(minMask) + fmt.Sprint(maxMask) // this name should be unique
	defset := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        prefixName,
		Prefixes:    []*bgpapi.Prefix{{IpPrefix: CIDR, MaskLengthMin: minMask, MaskLengthMax: maxMask}},
	}
	return defset, matchSetType, routeAction, prefixName, nil

}
func (s *Server) addStatementToPolicy(pol *bgpapi.Policy, routeAction bgpapi.RouteAction, neighborName string, prefixName string, matchSetType bgpapi.MatchSet_Type) {
	pol.Statements = append(pol.Statements,
		&bgpapi.Statement{
			Actions: &bgpapi.Actions{
				RouteAction: routeAction,
			},
			Conditions: &bgpapi.Conditions{
				NeighborSet: &bgpapi.MatchSet{
					Name: neighborName,
					Type: bgpapi.MatchSet_ANY,
				},
				PrefixSet: &bgpapi.MatchSet{
					Name: prefixName,
					Type: matchSetType,
				},
			},
		},
	)
}

func (s *Server) NewBGPPolicyAndAssignment(name string, rulesv4 []calicov3.BGPFilterRuleV4, rulesv6 []calicov3.BGPFilterRuleV6, neighborName string, dir bgpapi.PolicyDirection) (*watchers.BGPPrefixesPolicyAndAssignment, error) {
	pol := &bgpapi.Policy{Name: name}
	prefixes := []*bgpapi.DefinedSet{}
	for _, rule := range rulesv6 {
		defset, matchSetType, routeAction, prefixName, err := s.NewBGPPolicyV4V6(rule.CIDR, rule.MatchOperator, rule.Action)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, defset)
		s.addStatementToPolicy(pol, routeAction, neighborName, prefixName, matchSetType)
	}
	for _, rule := range rulesv4 {
		defset, matchSetType, routeAction, prefixName, err := s.NewBGPPolicyV4V6(rule.CIDR, rule.MatchOperator, rule.Action)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, defset)
		s.addStatementToPolicy(pol, routeAction, neighborName, prefixName, matchSetType)
	}
	PA := &bgpapi.PolicyAssignment{
		Name:          "global",
		Direction:     dir,
		Policies:      []*bgpapi.Policy{pol},
		DefaultAction: bgpapi.RouteAction_ACCEPT,
	}
	return &watchers.BGPPrefixesPolicyAndAssignment{PolicyAssignment: PA, Policy: pol, Prefixes: prefixes}, nil
}

// filterPeer creates policies in gobgp representing bgpfilters for the peer
func (s *Server) filterPeer(peerAddress string, filterNames []string) (map[string]*watchers.ImpExpPol, error) {
	BGPPolicies := make(map[string]*watchers.ImpExpPol)
	if len(filterNames) != 0 {
		s.log.Infof("Peer: (neighbor=%s) has filters, applying filters %s ...", peerAddress, filterNames)
		for _, filterName := range filterNames {
			_, ok := s.bgpFilters[filterName]
			if !ok {
				s.log.Warnf("peer (neighbor=%s) uses filter %s that does not exist yet", peerAddress, filterName)
				// save state for late filter creation
				BGPPolicies[filterName] = nil
			} else {
				impExpPol, err := s.createFilterPolicy(peerAddress, filterName, peerAddress+"neighbor")
				if err != nil {
					return nil, errors.Wrapf(err, "error creating filter policy")
				}
				BGPPolicies[filterName] = impExpPol
			}
		}
	}
	return BGPPolicies, nil
}

// createFilterPolicy creates policies in gobgp using filter prefix and neighbor
func (s *Server) createFilterPolicy(peerAddress string, filterName string, neighborSet string) (*watchers.ImpExpPol, error) {
	s.log.Infof("Creating policies for: (peer: %s, filter: %s, neighborSet: %s)", peerAddress, filterName, neighborSet)
	filter := s.bgpFilters[filterName]
	imppol, err := s.NewBGPPolicyAndAssignment("import-"+peerAddress+"-"+filterName, filter.Spec.ImportV4, filter.Spec.ImportV6, neighborSet, bgpapi.PolicyDirection_IMPORT)
	if err != nil {
		return nil, err
	}
	exppol, err := s.NewBGPPolicyAndAssignment("export-"+peerAddress+"-"+filterName, filter.Spec.ExportV4, filter.Spec.ExportV6, neighborSet, bgpapi.PolicyDirection_EXPORT)
	if err != nil {
		return nil, err
	}
	for _, pol := range []*watchers.BGPPrefixesPolicyAndAssignment{imppol, exppol} {
		for _, defset := range pol.Prefixes {
			err := s.BGPServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{
				DefinedSet: defset,
			})
			if err != nil {
				return nil, err
			}
		}
		err = s.BGPServer.AddPolicy(context.Background(), &bgpapi.AddPolicyRequest{Policy: pol.Policy})
		if err != nil {
			return nil, errors.Wrapf(err, "error adding policy")
		}
		err = s.BGPServer.AddPolicyAssignment(context.Background(), &bgpapi.AddPolicyAssignmentRequest{Assignment: pol.PolicyAssignment})
		if err != nil {
			return nil, errors.Wrapf(err, "error adding policy assignment")
		}
	}
	return &watchers.ImpExpPol{Imp: imppol, Exp: exppol}, nil
}

// deleteFilterPolicy deletes policies and their assignments in gobgp
func (s *Server) deleteFilterPolicy(impExpPol *watchers.ImpExpPol) error {
	for _, pol := range []*watchers.BGPPrefixesPolicyAndAssignment{impExpPol.Imp, impExpPol.Exp} {
		err := s.BGPServer.DeletePolicyAssignment(context.Background(), &bgpapi.DeletePolicyAssignmentRequest{Assignment: pol.PolicyAssignment})
		if err != nil {
			return errors.Wrapf(err, "error deleting policy assignment")
		}
		err = s.BGPServer.DeletePolicy(context.Background(), &bgpapi.DeletePolicyRequest{Policy: pol.Policy, All: true})
		if err != nil {
			return errors.Wrapf(err, "error deleting policy assignment")
		}
		for _, defset := range pol.Prefixes {
			err = s.BGPServer.DeleteDefinedSet(context.Background(), &bgpapi.DeleteDefinedSetRequest{DefinedSet: defset, All: true})
			if err != nil {
				return errors.Wrapf(err, "error deleting prefix set")
			}
		}
	}
	return nil
}

// cleanUpPeerFilters cleans up policies for a particular peer, from gobgp and saved state
func (s *Server) cleanUpPeerFilters(peerAddr string) error {
	polToDelete := []string{}
	for name, impExpPol := range s.bgpPeers[peerAddr].BGPPolicies {
		s.log.Infof("deleting filter: %s", name)
		err := s.deleteFilterPolicy(impExpPol)
		if err != nil {
			return errors.Wrapf(err, "error deleting filter policies")
		}
		polToDelete = append(polToDelete, name)
	}
	for _, name := range polToDelete {
		delete(s.bgpPeers[peerAddr].BGPPolicies, name)
	}
	return nil
}

// watchBGPPath watches BGP routes from other peers and inject them into linux kernel
// TODO: multipath support
func (s *Server) WatchBGPPath(t *tomb.Tomb) error {
	stopBGPMonitoring, err := s.startBGPMonitoring()
	if err != nil {
		return errors.Wrap(err, "error starting BGP monitoring")
	}

	for {
		select {
		case <-t.Dying():
			stopBGPMonitoring()
			s.log.Infof("Routing Server asked to stop")
			return nil
		case evt := <-s.routingServerEventChan:
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.LocalPodAddressAdded:
				networkPod, ok := evt.New.(cni.NetworkPod)
				if !ok {
					return fmt.Errorf("evt.New is not a (cni.NetworkPod) %v", evt.New)
				}
				err := s.announceLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
				if err != nil {
					return err
				}
			case common.LocalPodAddressDeleted:
				networkPod, ok := evt.Old.(cni.NetworkPod)
				if !ok {
					return fmt.Errorf("evt.Old is not a (cni.NetworkPod) %v", evt.Old)
				}
				err := s.withdrawLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
				if err != nil {
					return err
				}
			case common.BGPPathAdded:
				path, ok := evt.New.(*bgpapi.Path)
				if !ok {
					return fmt.Errorf("evt.New is not a (*bgpapi.Path) %v", evt.New)
				}
				_, err = s.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
					TableType: bgpapi.TableType_GLOBAL,
					Path:      path,
				})
				if err != nil {
					return err
				}
			case common.BGPPathDeleted:
				path, ok := evt.Old.(*bgpapi.Path)
				if !ok {
					return fmt.Errorf("evt.Old is not a (*bgpapi.Path) %v", evt.Old)
				}
				err = s.BGPServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
					TableType: bgpapi.TableType_GLOBAL,
					Path:      path,
				})
				if err != nil {
					return err
				}
			case common.BGPDefinedSetAdded:
				ps, ok := evt.New.(*bgpapi.DefinedSet)
				if !ok {
					return fmt.Errorf("evt.New is not a (*bgpapi.DefinedSet) %v", evt.New)
				}
				err := s.BGPServer.AddDefinedSet(
					context.Background(),
					&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
				)
				if err != nil {
					return err
				}
			case common.BGPDefinedSetDeleted:
				ps, ok := evt.Old.(*bgpapi.DefinedSet)
				if !ok {
					return fmt.Errorf("evt.Old is not a (*bgpapi.DefinedSet) %v", evt.Old)
				}
				err := s.BGPServer.DeleteDefinedSet(
					context.Background(),
					&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
				)
				if err != nil {
					return err
				}
			case common.BGPPeerAdded:
				localPeer, ok := evt.New.(*watchers.LocalBGPPeer)
				if !ok {
					return fmt.Errorf("evt.New is not a (*watchers.LocalBGPPeer) %v", evt.New)
				}
				peer := localPeer.Peer
				filters := localPeer.BGPFilterNames
				// create a neighbor set to apply filter only on specific peer using a global policy
				prefixLen := "/32"
				if ip := net.ParseIP(peer.Conf.NeighborAddress); ip != nil && ip.To4() == nil {
					prefixLen = "/128"
				}
				neighborSet := &bgpapi.DefinedSet{
					Name:        peer.Conf.NeighborAddress + "neighbor",
					DefinedType: bgpapi.DefinedType_NEIGHBOR,
					List:        []string{peer.Conf.NeighborAddress + prefixLen},
				}
				err := s.BGPServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{
					DefinedSet: neighborSet,
				})
				if err != nil {
					return errors.Wrapf(err, "error creating neighbor set")
				}
				BGPPolicies, err := s.filterPeer(peer.Conf.NeighborAddress, filters)
				if err != nil {
					return errors.Wrapf(err, "error filetring peer")
				}
				s.log.Infof("bgp(add) new neighbor=%s AS=%d",
					peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
				err = s.BGPServer.AddPeer(
					context.Background(),
					&bgpapi.AddPeerRequest{Peer: peer},
				)
				if err != nil {
					return err
				}
				localPeer.BGPPolicies = BGPPolicies
				localPeer.NeighborSet = neighborSet
				s.bgpPeers[peer.Conf.NeighborAddress] = localPeer
			case common.BGPPeerDeleted:
				addr, ok := evt.New.(string)
				if !ok {
					return fmt.Errorf("evt.New is not a (string) %v", evt.New)
				}
				s.log.Infof("bgp(del) neighbor=%s", addr)
				err = s.cleanUpPeerFilters(addr)
				if err != nil {
					return errors.Wrapf(err, "error cleaning peer filters up")
				}
				if s.bgpPeers[addr] == nil {
					s.log.Warnf("Trying to delete unknown BGP peer %s", addr)
				} else if s.bgpPeers[addr].NeighborSet == nil {
					s.log.Warnf("Trying to delete BGP peer %s with empty NeighborSet", addr)
				} else {
					err = s.BGPServer.DeleteDefinedSet(context.Background(), &bgpapi.DeleteDefinedSetRequest{
						DefinedSet: s.bgpPeers[addr].NeighborSet,
						All:        true,
					})
					if err != nil {
						return errors.Wrapf(err, "error deleting prefix set")
					}
				}
				err := s.BGPServer.DeletePeer(
					context.Background(),
					&bgpapi.DeletePeerRequest{Address: addr},
				)
				if err != nil {
					return err
				}
				delete(s.bgpPeers, addr)
			case common.BGPPeerUpdated:
				oldPeer, ok := evt.Old.(*watchers.LocalBGPPeer)
				if !ok {
					return fmt.Errorf("evt.Old is not (*watchers.LocalBGPPeer) %v", evt.Old)
				}
				localPeer, ok := evt.New.(*watchers.LocalBGPPeer)
				if !ok {
					return fmt.Errorf("evt.New is not (*watchers.LocalBGPPeer %v", evt.New)
				}
				peer := localPeer.Peer
				filters := localPeer.BGPFilterNames
				s.log.Infof("bgp(upd) neighbor=%s", peer.Conf.NeighborAddress)
				var BGPPolicies map[string]*watchers.ImpExpPol
				if !watchers.CompareStringSlices(localPeer.BGPFilterNames, oldPeer.BGPFilterNames) { // update filters
					err = s.cleanUpPeerFilters(peer.Conf.NeighborAddress)
					if err != nil {
						return errors.Wrapf(err, "error cleaning peer filters up")
					}
					BGPPolicies, err = s.filterPeer(peer.Conf.NeighborAddress, filters)
					if err != nil {
						return errors.Wrapf(err, "error filetring peer")
					}
				}
				s.log.Infof("bgp(upd) neighbor=%s AS=%d",
					peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
				_, err = s.BGPServer.UpdatePeer(
					context.Background(),
					&bgpapi.UpdatePeerRequest{Peer: peer},
				)
				if err != nil {
					return err
				}
				localPeer.BGPPolicies = BGPPolicies
				s.bgpPeers[peer.Conf.NeighborAddress] = localPeer
			case common.BGPFilterAddedOrUpdated:
				filter, ok := evt.New.(calicov3.BGPFilter)
				if !ok {
					return fmt.Errorf("evt.New is not (calicov3.BGPFilter) %v", evt.New)
				}
				s.log.Infof("bgp(add/upd) filter: %s", filter.Name)
				s.bgpFilters[filter.Name] = &filter
				// If this filter is already used in gobgp, delete old policies if any and recreate them
				for peerAddress := range s.bgpPeers {
					if impExpPol, ok := s.bgpPeers[peerAddress].BGPPolicies[filter.Name]; ok {
						s.log.Infof("filter used in %s, updating filter", peerAddress)
						if impExpPol != nil {
							err := s.deleteFilterPolicy(impExpPol)
							if err != nil {
								return errors.Wrap(err, "error deleting filter policies")
							}
						} // else we received peer using a filter before receiving the filter, so just create it
						impExpPol, err := s.createFilterPolicy(peerAddress, filter.Name, peerAddress+"neighbor")
						if err != nil {
							return errors.Wrap(err, "error creating filters")
						}
						s.bgpPeers[peerAddress].BGPPolicies[filter.Name] = impExpPol
						// have to update peers to apply changes
						_, err = s.BGPServer.UpdatePeer(
							context.Background(),
							&bgpapi.UpdatePeerRequest{Peer: s.bgpPeers[peerAddress].Peer},
						)
						if err != nil {
							return errors.Wrapf(err, "error updating peer %s", peerAddress)
						}
					}
				}
			case common.BGPFilterDeleted: // supposed to rely on user to never delete a used bgpfilter
				filter, ok := evt.Old.(calicov3.BGPFilter)
				if !ok {
					return fmt.Errorf("evt.Old is not (calicov3.BGPFilter) %v", evt.Old)
				}
				s.log.Infof("bgp(del) filter deleted: %s", filter.Name)
				delete(s.bgpFilters, filter.Name)
			}
		}
	}
}
