// Copyright (C) 2020 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routing

import (
	"fmt"
	"net"
	"reflect"
	"sort"

	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// LocalBGPPeer represents a BGP peer with its configuration and policies
type LocalBGPPeer struct {
	Peer           *bgpapi.Peer
	BGPFilterNames []string
	BGPPolicies    map[string]*ImpExpPol
	NeighborSet    *bgpapi.DefinedSet
}

// BGPPrefixesPolicyAndAssignment contains BGP policy and prefix information
type BGPPrefixesPolicyAndAssignment struct {
	PolicyAssignment *bgpapi.PolicyAssignment
	Policy           *bgpapi.Policy
	Prefixes         []*bgpapi.DefinedSet
}

// ImpExpPol contains import and export policies
type ImpExpPol struct {
	Imp *BGPPrefixesPolicyAndAssignment
	Exp *BGPPrefixesPolicyAndAssignment
}

// BGPHandler handles BGP business logic operations
type BGPHandler struct {
	log        *logrus.Entry
	BGPServer  *bgpserver.BgpServer
	bgpFilters map[string]*calicov3.BGPFilter
	bgpPeers   map[string]*LocalBGPPeer
}

// NewBGPHandler creates a new BGP handler instance
func NewBGPHandler(log *logrus.Entry) *BGPHandler {
	return &BGPHandler{
		log:        log,
		bgpFilters: make(map[string]*calicov3.BGPFilter),
		bgpPeers:   make(map[string]*LocalBGPPeer),
	}
}

// SetBGPServer sets the BGP server instance
func (h *BGPHandler) SetBGPServer(bgpServer *bgpserver.BgpServer) {
	h.BGPServer = bgpServer
}

// getNexthop extracts the next hop from BGP path attributes
func (h *BGPHandler) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := attr.UnmarshalTo(nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := attr.UnmarshalTo(mpReachAttr); err == nil {
			if len(mpReachAttr.NextHops) != 1 {
				h.log.Fatalf("Cannot process more than one Nlri in path attributes: %+v", mpReachAttr)
			}
			return mpReachAttr.NextHops[0]
		}
	}
	return ""
}

// CompareStringSlices compares two string slices for equality (order-independent)
func CompareStringSlices(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	// Sort the slices in ascending order
	sort.Strings(slice1)
	sort.Strings(slice2)

	// Compare the sorted slices
	return reflect.DeepEqual(slice1, slice2)
}

// injectRoute is a helper function to inject BGP routes to VPP
// TODO: multipath support
func (h *BGPHandler) InjectRoute(path *bgpapi.Path) error {
	var dst net.IPNet
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	labeledVPNIPAddressPrefixNlri := &bgpapi.LabeledVPNIPAddressPrefix{}
	vpn := false
	otherNodeIP := net.ParseIP(h.getNexthop(path))
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

func (h *BGPHandler) getSRPolicy(path *bgpapi.Path) (srv6Policy *types.SrPolicy, srv6tunnel *common.SRv6Tunnel, srnrli *bgpapi.SRPolicyNLRI, err error) {
	srnrli = &bgpapi.SRPolicyNLRI{}
	tun := &bgpapi.TunnelEncapAttribute{}
	subTLVSegList := &bgpapi.TunnelEncapSubTLVSRSegmentList{}
	segments := []*bgpapi.SegmentTypeB{}
	srv6bsid := &bgpapi.SRBindingSID{}
	srv6tunnel = &common.SRv6Tunnel{}

	if err := path.Nlri.UnmarshalTo(srnrli); err != nil {
		return nil, nil, nil, err
	}
	srv6tunnel.Dst = net.IP(srnrli.Endpoint)

	for _, pattr := range path.Pattrs {
		if err := pattr.UnmarshalTo(tun); err == nil {
			for _, tlv := range tun.Tlvs {
				// unmarshal Tlvs
				for _, innerTlv := range tlv.Tlvs {
					// search for TunnelEncapSubTLVSRSegmentList
					if err := innerTlv.UnmarshalTo(subTLVSegList); err == nil {
						for _, seglist := range subTLVSegList.Segments {
							segment := &bgpapi.SegmentTypeB{}
							if err = seglist.UnmarshalTo(segment); err == nil {
								segments = append(segments, segment)
							}
						}
					}
					// search for TunnelEncapSubTLVSRBindingSID
					srbsids := &anypb.Any{}
					if err := innerTlv.UnmarshalTo(srbsids); err == nil {
						h.log.Debugf("getSRPolicy TunnelEncapSubTLVSRBindingSID")
						if err := srbsids.UnmarshalTo(srv6bsid); err != nil {
							return nil, nil, nil, err
						}
					}

					// search for TunnelEncapSubTLVSRPriority
					subTLVSRPriority := &bgpapi.TunnelEncapSubTLVSRPriority{}
					if err := innerTlv.UnmarshalTo(subTLVSRPriority); err == nil {
						h.log.Debugf("getSRPolicyPriority TunnelEncapSubTLVSRPriority")
						srv6tunnel.Priority = subTLVSRPriority.Priority
					}
				}
			}
		}
	}

	policySidListsids := [16]ip_types.IP6Address{}
	for i, segment := range segments {
		policySidListsids[i] = types.ToVppIP6Address(net.IP(segment.Sid))
	}
	srv6Policy = &types.SrPolicy{
		Bsid:     types.ToVppIP6Address(net.IP(srv6bsid.Sid)),
		IsSpray:  false,
		IsEncap:  true,
		FibTable: 0,
		SidLists: []types.Srv6SidList{{
			NumSids: uint8(len(segments)),
			Weight:  1,
			Sids:    policySidListsids,
		}},
	}
	srv6tunnel.Bsid = srv6Policy.Bsid.ToIP()
	srv6tunnel.Policy = srv6Policy

	srv6tunnel.Behavior = uint8(segments[len(segments)-1].GetEndpointBehaviorStructure().Behavior)

	return srv6Policy, srv6tunnel, srnrli, err
}

func (h *BGPHandler) InjectSRv6Policy(path *bgpapi.Path) error {
	_, srv6tunnel, srnrli, err := h.getSRPolicy(path)

	if err != nil {
		return errors.Wrap(err, "error injectSRv6Policy")
	}

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

// NewBGPPolicyV4V6 creates BGP policy for IPv4/IPv6 CIDR filtering
func (h *BGPHandler) NewBGPPolicyV4V6(CIDR string, matchOperator calicov3.BGPFilterMatchOperator, action calicov3.BGPFilterAction) (*bgpapi.DefinedSet, bgpapi.MatchSet_Type, bgpapi.RouteAction, string, error) {
	routeAction := bgpapi.RouteAction_ACCEPT
	if action == calicov3.Reject {
		routeAction = bgpapi.RouteAction_REJECT
	} else if action != calicov3.Accept {
		return nil, 0, 0, "", errors.Errorf("error creating new bgp policy: action %s not supported", action)
	}

	var matchSetType bgpapi.MatchSet_Type
	var minMask, maxMask uint32
	if matchOperator == calicov3.In || matchOperator == calicov3.NotIn {
		_, subnet, err := net.ParseCIDR(CIDR)
		if err != nil {
			return nil, 0, 0, "", errors.Wrap(err, "error creating new bgp policy")
		}
		ones, bits := subnet.Mask.Size()
		minMask = uint32(ones)
		maxMask = uint32(bits)
		if matchOperator == calicov3.In {
			matchSetType = bgpapi.MatchSet_ANY // any and all are same in our case as we have only one member of the defined set
		} else {
			matchSetType = bgpapi.MatchSet_INVERT
		}
	} else {
		// mask is zero
		if matchOperator == calicov3.Equal {
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

// addStatementToPolicy adds a statement to a BGP policy
func (h *BGPHandler) addStatementToPolicy(pol *bgpapi.Policy, routeAction bgpapi.RouteAction, neighborName string, prefixName string, matchSetType bgpapi.MatchSet_Type) {
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

// NewBGPPolicyAndAssignment creates BGP policy and assignment from filter rules
func (h *BGPHandler) NewBGPPolicyAndAssignment(name string, rulesv4 []calicov3.BGPFilterRuleV4, rulesv6 []calicov3.BGPFilterRuleV6, neighborName string, dir bgpapi.PolicyDirection) (*BGPPrefixesPolicyAndAssignment, error) {
	pol := &bgpapi.Policy{Name: name}
	prefixes := []*bgpapi.DefinedSet{}

	for _, rule := range rulesv6 {
		defset, matchSetType, routeAction, prefixName, err := h.NewBGPPolicyV4V6(rule.CIDR, rule.MatchOperator, rule.Action)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, defset)
		h.addStatementToPolicy(pol, routeAction, neighborName, prefixName, matchSetType)
	}

	for _, rule := range rulesv4 {
		defset, matchSetType, routeAction, prefixName, err := h.NewBGPPolicyV4V6(rule.CIDR, rule.MatchOperator, rule.Action)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, defset)
		h.addStatementToPolicy(pol, routeAction, neighborName, prefixName, matchSetType)
	}

	PA := &bgpapi.PolicyAssignment{
		Name:          "global",
		Direction:     dir,
		Policies:      []*bgpapi.Policy{pol},
		DefaultAction: bgpapi.RouteAction_ACCEPT,
	}
	return &BGPPrefixesPolicyAndAssignment{PolicyAssignment: PA, Policy: pol, Prefixes: prefixes}, nil
}

// filterPeer creates policies in gobgp representing bgpfilters for the peer
func (h *BGPHandler) filterPeer(peerAddress string, filterNames []string) (map[string]*ImpExpPol, error) {
	BGPPolicies := make(map[string]*ImpExpPol)
	if len(filterNames) != 0 {
		h.log.Infof("Peer: (neighbor=%s) has filters, applying filters %s ...", peerAddress, filterNames)
		for _, filterName := range filterNames {
			_, ok := h.bgpFilters[filterName]
			if !ok {
				h.log.Warnf("peer (neighbor=%s) uses filter %s that does not exist yet", peerAddress, filterName)
				// save state for late filter creation
				BGPPolicies[filterName] = nil
			} else {
				impExpPol, err := h.createFilterPolicy(peerAddress, filterName, peerAddress+"neighbor")
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
func (h *BGPHandler) createFilterPolicy(peerAddress string, filterName string, neighborSet string) (*ImpExpPol, error) {
	h.log.Infof("Creating policies for: (peer: %s, filter: %s, neighborSet: %s)", peerAddress, filterName, neighborSet)
	filter := h.bgpFilters[filterName]
	imppol, err := h.NewBGPPolicyAndAssignment("import-"+peerAddress+"-"+filterName, filter.Spec.ImportV4, filter.Spec.ImportV6, neighborSet, bgpapi.PolicyDirection_IMPORT)
	if err != nil {
		return nil, err
	}
	exppol, err := h.NewBGPPolicyAndAssignment("export-"+peerAddress+"-"+filterName, filter.Spec.ExportV4, filter.Spec.ExportV6, neighborSet, bgpapi.PolicyDirection_EXPORT)
	if err != nil {
		return nil, err
	}

	for _, pol := range []*BGPPrefixesPolicyAndAssignment{imppol, exppol} {
		for _, defset := range pol.Prefixes {
			err := h.BGPServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{
				DefinedSet: defset,
			})
			if err != nil {
				return nil, err
			}
		}
		err = h.BGPServer.AddPolicy(context.Background(), &bgpapi.AddPolicyRequest{Policy: pol.Policy})
		if err != nil {
			return nil, errors.Wrapf(err, "error adding policy")
		}
		err = h.BGPServer.AddPolicyAssignment(context.Background(), &bgpapi.AddPolicyAssignmentRequest{Assignment: pol.PolicyAssignment})
		if err != nil {
			return nil, errors.Wrapf(err, "error adding policy assignment")
		}
	}
	return &ImpExpPol{Imp: imppol, Exp: exppol}, nil
}

// deleteFilterPolicy deletes policies and their assignments in gobgp
func (h *BGPHandler) deleteFilterPolicy(impExpPol *ImpExpPol) error {
	for _, pol := range []*BGPPrefixesPolicyAndAssignment{impExpPol.Imp, impExpPol.Exp} {
		err := h.BGPServer.DeletePolicyAssignment(context.Background(), &bgpapi.DeletePolicyAssignmentRequest{Assignment: pol.PolicyAssignment})
		if err != nil {
			return errors.Wrapf(err, "error deleting policy assignment")
		}
		err = h.BGPServer.DeletePolicy(context.Background(), &bgpapi.DeletePolicyRequest{Policy: pol.Policy, All: true})
		if err != nil {
			return errors.Wrapf(err, "error deleting policy assignment")
		}
		for _, defset := range pol.Prefixes {
			err = h.BGPServer.DeleteDefinedSet(context.Background(), &bgpapi.DeleteDefinedSetRequest{DefinedSet: defset, All: true})
			if err != nil {
				return errors.Wrapf(err, "error deleting prefix set")
			}
		}
	}
	return nil
}

// cleanUpPeerFilters cleans up policies for a particular peer, from gobgp and saved state
func (h *BGPHandler) cleanUpPeerFilters(peerAddr string) error {
	polToDelete := []string{}
	for name, impExpPol := range h.bgpPeers[peerAddr].BGPPolicies {
		h.log.Infof("deleting filter: %s", name)
		err := h.deleteFilterPolicy(impExpPol)
		if err != nil {
			return errors.Wrapf(err, "error deleting filter policies")
		}
		polToDelete = append(polToDelete, name)
	}
	for _, name := range polToDelete {
		delete(h.bgpPeers[peerAddr].BGPPolicies, name)
	}
	return nil
}

// createEmptyPrefixSet creates an empty prefix set for BGP policies
func (h *BGPHandler) createEmptyPrefixSet(name string) error {
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        name,
	}
	err := h.BGPServer.AddDefinedSet(
		context.Background(),
		&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
	)
	if err != nil {
		return errors.Wrapf(err, "error creating prefix set %s", name)
	}
	return nil
}

// InitialPolicySetting initializes BGP export policy.
// this creates two prefix-sets named 'aggregated' and 'host'.
// A route is allowed to be exported when it matches with 'aggregated' set,
// and not allowed when it matches with 'host' set.
func (h *BGPHandler) InitialPolicySetting(isv6 bool) error {
	aggregatedPrefixSetName := common.GetAggPrefixSetName(isv6)
	hostPrefixSetName := common.GetHostPrefixSetName(isv6)
	err := h.createEmptyPrefixSet(aggregatedPrefixSetName)
	if err != nil {
		return err
	}
	err = h.createEmptyPrefixSet(hostPrefixSetName)
	if err != nil {
		return err
	}
	// intended to work as same as 'calico_pools' export filter of BIRD configuration
	definition := &bgpapi.Policy{
		Name: common.GetPolicyName(isv6),
		Statements: []*bgpapi.Statement{
			{
				Conditions: &bgpapi.Conditions{
					PrefixSet: &bgpapi.MatchSet{
						Type: bgpapi.MatchSet_ANY,
						Name: aggregatedPrefixSetName,
					},
				},
				Actions: &bgpapi.Actions{
					RouteAction: bgpapi.RouteAction_ACCEPT,
				},
			},
			{
				Conditions: &bgpapi.Conditions{
					PrefixSet: &bgpapi.MatchSet{
						Type: bgpapi.MatchSet_ANY,
						Name: hostPrefixSetName,
					},
				},
				Actions: &bgpapi.Actions{
					RouteAction: bgpapi.RouteAction_REJECT,
				},
			},
		},
	}

	err = h.BGPServer.AddPolicy(
		context.Background(),
		&bgpapi.AddPolicyRequest{
			Policy:                  definition,
			ReferExistingStatements: false,
		},
	)
	if err != nil {
		return errors.Wrap(err, "error adding policy")
	}
	err = h.BGPServer.AddPolicyAssignment(
		context.Background(),
		&bgpapi.AddPolicyAssignmentRequest{
			Assignment: &bgpapi.PolicyAssignment{
				Name:          "global",
				Direction:     bgpapi.PolicyDirection_EXPORT,
				Policies:      []*bgpapi.Policy{definition},
				DefaultAction: bgpapi.RouteAction_ACCEPT,
			},
		})
	if err != nil {
		return errors.Wrap(err, "cannot add policy assignment")
	}
	return nil
}

// HandleBGPPeerAdded handles BGP peer addition directly
func (h *BGPHandler) HandleBGPPeerAdded(localPeer *LocalBGPPeer) error {
	h.log.Debugf("BGP handler processing BGP peer added")
	peer := localPeer.Peer
	filters := localPeer.BGPFilterNames

	// create a neighbor set to apply filter only on specific peer using a global policy
	neighborSet := &bgpapi.DefinedSet{
		Name:        peer.Conf.NeighborAddress + "neighbor",
		DefinedType: bgpapi.DefinedType_NEIGHBOR,
		List:        []string{peer.Conf.NeighborAddress + "/32"},
	}
	err := h.BGPServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{
		DefinedSet: neighborSet,
	})
	if err != nil {
		return errors.Wrapf(err, "error creating neighbor set")
	}

	BGPPolicies, err := h.filterPeer(peer.Conf.NeighborAddress, filters)
	if err != nil {
		return errors.Wrapf(err, "error filtering peer")
	}

	h.log.Infof("bgp(add) new neighbor=%s AS=%d", peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
	err = h.BGPServer.AddPeer(
		context.Background(),
		&bgpapi.AddPeerRequest{Peer: peer},
	)
	if err != nil {
		return err
	}

	localPeer.BGPPolicies = BGPPolicies
	localPeer.NeighborSet = neighborSet
	h.bgpPeers[peer.Conf.NeighborAddress] = localPeer
	return nil
}

// HandleBGPPeerUpdated handles BGP peer updates directly
func (h *BGPHandler) HandleBGPPeerUpdated(localPeer *LocalBGPPeer, oldPeer *LocalBGPPeer) error {
	h.log.Debugf("BGP handler processing BGP peer updated")
	peer := localPeer.Peer
	filters := localPeer.BGPFilterNames
	h.log.Infof("bgp(upd) neighbor=%s", peer.Conf.NeighborAddress)

	var BGPPolicies map[string]*ImpExpPol
	if !CompareStringSlices(localPeer.BGPFilterNames, oldPeer.BGPFilterNames) { // update filters
		err := h.cleanUpPeerFilters(peer.Conf.NeighborAddress)
		if err != nil {
			return errors.Wrapf(err, "error cleaning peer filters up")
		}
		BGPPolicies, err = h.filterPeer(peer.Conf.NeighborAddress, filters)
		if err != nil {
			return errors.Wrapf(err, "error filtering peer")
		}
	}

	h.log.Infof("bgp(upd) neighbor=%s AS=%d", peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
	_, err := h.BGPServer.UpdatePeer(
		context.Background(),
		&bgpapi.UpdatePeerRequest{Peer: peer},
	)
	if err != nil {
		return err
	}

	localPeer.BGPPolicies = BGPPolicies
	h.bgpPeers[peer.Conf.NeighborAddress] = localPeer
	return nil
}

// HandleBGPPeerDeleted handles BGP peer deletion directly
func (h *BGPHandler) HandleBGPPeerDeleted(peerIP string) error {
	h.log.Debugf("BGP handler processing BGP peer deleted")
	localPeer, found := h.bgpPeers[peerIP]
	if !found {
		h.log.Warnf("BGP peer %s not found for deletion", peerIP)
		return nil
	}

	err := h.BGPServer.DeletePeer(context.Background(), &bgpapi.DeletePeerRequest{
		Address: peerIP,
	})
	if err != nil {
		return errors.Wrapf(err, "error deleting BGP peer %s", peerIP)
	}

	// Clean up filters and neighbor set
	err = h.cleanUpPeerFilters(peerIP)
	if err != nil {
		h.log.Warnf("Error cleaning up peer filters for %s: %v", peerIP, err)
	}

	if localPeer.NeighborSet != nil {
		err = h.BGPServer.DeleteDefinedSet(context.Background(), &bgpapi.DeleteDefinedSetRequest{
			DefinedSet: localPeer.NeighborSet,
		})
		if err != nil {
			h.log.Warnf("Error deleting neighbor set for %s: %v", peerIP, err)
		}
	}

	delete(h.bgpPeers, peerIP)
	return nil
}

// HandleBGPFilterAddedOrUpdated handles BGP filter addition or update directly
func (h *BGPHandler) HandleBGPFilterAddedOrUpdated(filter calicov3.BGPFilter) error {
	h.log.Infof("bgp(add/upd) filter: %s", filter.Name)
	h.bgpFilters[filter.Name] = &filter

	// If this filter is already used in gobgp, delete old policies if any and recreate them
	for peerAddress := range h.bgpPeers {
		if impExpPol, ok := h.bgpPeers[peerAddress].BGPPolicies[filter.Name]; ok {
			h.log.Infof("filter used in %s, updating filter", peerAddress)
			if impExpPol != nil {
				err := h.deleteFilterPolicy(impExpPol)
				if err != nil {
					return errors.Wrap(err, "error deleting filter policies")
				}
			} // else we received peer using a filter before receiving the filter, so just create it

			impExpPol, err := h.createFilterPolicy(peerAddress, filter.Name, peerAddress+"neighbor")
			if err != nil {
				return errors.Wrapf(err, "error creating filter policy")
			}
			h.bgpPeers[peerAddress].BGPPolicies[filter.Name] = impExpPol

			// have to update peers to apply changes
			_, err2 := h.BGPServer.UpdatePeer(
				context.Background(),
				&bgpapi.UpdatePeerRequest{Peer: h.bgpPeers[peerAddress].Peer},
			)
			if err2 != nil {
				return errors.Wrapf(err2, "error updating peer %s", peerAddress)
			}
		}
	}
	return nil
}

// HandleBGPFilterDeleted handles BGP filter deletion directly
func (h *BGPHandler) HandleBGPFilterDeleted(filter calicov3.BGPFilter) error {
	h.log.Infof("bgp(del) filter deleted: %s", filter.Name)
	delete(h.bgpFilters, filter.Name)
	return nil
}

// HandleBGPDefinedSetAdded handles BGP defined set addition directly
func (h *BGPHandler) HandleBGPDefinedSetAdded(definedSet *bgpapi.DefinedSet) error {
	h.log.Debugf("BGP handler processing defined set added")
	err := h.BGPServer.AddDefinedSet(
		context.Background(),
		&bgpapi.AddDefinedSetRequest{DefinedSet: definedSet},
	)
	if err != nil {
		return err
	}
	return nil
}

// HandleBGPDefinedSetDeleted handles BGP defined set deletion directly
func (h *BGPHandler) HandleBGPDefinedSetDeleted(definedSet *bgpapi.DefinedSet) error {
	h.log.Debugf("BGP handler processing defined set deleted")
	err := h.BGPServer.DeleteDefinedSet(
		context.Background(),
		&bgpapi.DeleteDefinedSetRequest{DefinedSet: definedSet, All: false},
	)
	if err != nil {
		return err
	}
	return nil
}

// HandleBGPPathAdded handles BGP path addition
func (h *BGPHandler) HandleBGPPathAdded(path *bgpapi.Path) error {
	h.log.Debugf("BGP handler processing BGP path added")
	_, err := h.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		Path: path,
	})
	if err != nil {
		return errors.Wrap(err, "error adding BGP path")
	}
	return nil
}

// HandleBGPPathDeleted handles BGP path deletion
func (h *BGPHandler) HandleBGPPathDeleted(path *bgpapi.Path) error {
	h.log.Debugf("BGP handler processing BGP path deleted")
	err := h.BGPServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
		Path: path,
	})
	if err != nil {
		return errors.Wrap(err, "error deleting BGP path")
	}
	return nil
}
