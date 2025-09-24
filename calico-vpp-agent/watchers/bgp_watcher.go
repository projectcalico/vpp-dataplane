// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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

package watchers

import (
	"fmt"
	"net"

	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"

	// needed for GoBGP building (in ../Makefile, gobp target)
	_ "github.com/inconshreveable/mousetrap"
	_ "github.com/spf13/cobra"
)

type BGPWatcher struct {
	log *logrus.Entry

	BGPConf     *calicov3.BGPConfigurationSpec
	BGPServer   *bgpserver.BgpServer
	bgpFilters  map[string]*calicov3.BGPFilter
	bgpPeers    map[string]*LocalBGPPeer
	nodeBGPSpec *common.LocalNodeSpec

	bgpWatcherEventChan     chan any
	routingHandlerEventChan chan any
}

func NewBGPWatcher(bgpServer *bgpserver.BgpServer, log *logrus.Entry) *BGPWatcher {
	watcher := &BGPWatcher{
		log:       log,
		BGPServer: bgpServer,

		bgpWatcherEventChan: make(chan any, common.ChanSize),
		bgpFilters:          make(map[string]*calicov3.BGPFilter),
		bgpPeers:            make(map[string]*LocalBGPPeer),
	}

	return watcher
}

func (w *BGPWatcher) GetEventChan() chan any {
	return w.bgpWatcherEventChan
}

func (w *BGPWatcher) SetRoutingHandlerEventChan(routingHandlerEventChan chan any) {
	w.routingHandlerEventChan = routingHandlerEventChan
}

func (w *BGPWatcher) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	w.BGPConf = bgpConf

	logLevel, err := logrus.ParseLevel(w.getLogSeverityScreen())
	if err != nil {
		w.log.WithError(err).Errorf("Failed to parse loglevel: %s, defaulting to info", w.getLogSeverityScreen())
	} else {
		logrus.SetLevel(logLevel)
	}
}

func (w *BGPWatcher) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	w.nodeBGPSpec = nodeBGPSpec
}

func (w *BGPWatcher) getListenPort() uint16 {
	return w.BGPConf.ListenPort
}

func (w *BGPWatcher) getLogSeverityScreen() string {
	return w.BGPConf.LogSeverityScreen
}

func (w *BGPWatcher) getGoBGPGlobalConfig() (*bgpapi.Global, error) {
	var routerID string
	listenAddresses := make([]string, 0)
	asn := w.nodeBGPSpec.ASNumber
	if asn == nil {
		asn = w.BGPConf.ASNumber
	}

	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	if nodeIP6 != nil {
		routerID = nodeIP6.String()
		listenAddresses = append(listenAddresses, routerID)
	}
	if nodeIP4 != nil {
		routerID = nodeIP4.String() // Override v6 ID if v4 is available
		listenAddresses = append(listenAddresses, routerID)
	}

	if routerID == "" {
		return nil, fmt.Errorf("no IPs to make a router ID")
	}
	return &bgpapi.Global{
		Asn:             uint32(*asn),
		RouterId:        routerID,
		ListenPort:      int32(w.getListenPort()),
		ListenAddresses: listenAddresses,
	}, nil
}

func (w *BGPWatcher) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := attr.UnmarshalTo(nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := attr.UnmarshalTo(mpReachAttr); err == nil {
			if len(mpReachAttr.NextHops) != 1 {
				w.log.Fatalf("Cannot process more than one Nlri in path attributes: %+v", mpReachAttr)
			}
			return mpReachAttr.NextHops[0]
		}
	}
	return ""
}

func (w *BGPWatcher) injectRoute(path *bgpapi.Path) error {
	w.log.Debugf("Injecting route: %s", path.Nlri)

	ipv4unicastNLRI := &bgpapi.IPAddressPrefix{}
	ipv6unicastNLRI := &bgpapi.IPAddressPrefix{}
	labeledVPNIPAddressPrefixNlri := &bgpapi.LabeledVPNIPAddressPrefix{}

	dst := &net.IPNet{}
	nexthop := w.getNexthop(path)
	vpn := false
	var cn *common.NodeConnectivity

	if err := path.Nlri.UnmarshalTo(ipv4unicastNLRI); err == nil {
		dst.IP = net.ParseIP(ipv4unicastNLRI.Prefix).To4()
		mask := net.CIDRMask(int(ipv4unicastNLRI.PrefixLen), 32)
		dst.Mask = mask
	} else if err := path.Nlri.UnmarshalTo(ipv6unicastNLRI); err == nil {
		dst.IP = net.ParseIP(ipv6unicastNLRI.Prefix).To16()
		mask := net.CIDRMask(int(ipv6unicastNLRI.PrefixLen), 128)
		dst.Mask = mask
	} else if err := path.Nlri.UnmarshalTo(labeledVPNIPAddressPrefixNlri); err == nil {
		vpn = true
		w.log.Debugf("BGP VPN update: %+v", labeledVPNIPAddressPrefixNlri)
		dst.IP = net.ParseIP(labeledVPNIPAddressPrefixNlri.Prefix)
		if dst.IP.To4() != nil {
			dst.IP = dst.IP.To4()
			mask := net.CIDRMask(int(labeledVPNIPAddressPrefixNlri.PrefixLen), 32)
			dst.Mask = mask
		} else {
			mask := net.CIDRMask(int(labeledVPNIPAddressPrefixNlri.PrefixLen), 128)
			dst.Mask = mask
		}
	} else {
		return errors.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}

	cn = &common.NodeConnectivity{
		Dst:     *dst,
		NextHop: net.ParseIP(nexthop),
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
		w.routingHandlerEventChan <- common.CalicoVppEvent{
			Type: common.ConnectivityDeleted,
			Old:  cn,
		}
	} else {
		w.routingHandlerEventChan <- common.CalicoVppEvent{
			Type: common.ConnectivityAdded,
			New:  cn,
		}
	}
	return nil
}

func (w *BGPWatcher) getSRPolicy(path *bgpapi.Path) (srv6Policy *types.SrPolicy, srv6tunnel *common.SRv6Tunnel, srnrli *bgpapi.SRPolicyNLRI, err error) {
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
						w.log.Debugf("getSRPolicy TunnelEncapSubTLVSRBindingSID")
						if err := srbsids.UnmarshalTo(srv6bsid); err != nil {
							return nil, nil, nil, err
						}

					}

					// search for TunnelEncapSubTLVSRPriority
					subTLVSRPriority := &bgpapi.TunnelEncapSubTLVSRPriority{}
					if err := innerTlv.UnmarshalTo(subTLVSRPriority); err == nil {
						w.log.Debugf("getSRPolicyPriority TunnelEncapSubTLVSRPriority")
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

func (w *BGPWatcher) injectSRv6Policy(path *bgpapi.Path) error {
	_, srv6tunnel, srnrli, err := w.getSRPolicy(path)

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
		w.routingHandlerEventChan <- common.CalicoVppEvent{
			Type: common.SRv6PolicyDeleted,
			Old:  cn,
		}
	} else {
		w.routingHandlerEventChan <- common.CalicoVppEvent{
			Type: common.SRv6PolicyAdded,
			New:  cn,
		}
	}
	return nil
}

func (w *BGPWatcher) startBGPMonitoring() (func(), error) {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	ctx, stopFunc := context.WithCancel(context.Background())
	err := w.BGPServer.WatchEvent(ctx,
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
						w.log.Warnf("nil path update, skipping")
						continue
					}
					if nodeIP4 == nil && path.GetFamily().Afi == bgpapi.Family_AFI_IP {
						w.log.Debugf("Ignoring ipv4 path with no node ip4")
						continue
					}
					if nodeIP6 == nil && path.GetFamily().Afi == bgpapi.Family_AFI_IP6 {
						w.log.Debugf("Ignoring ipv6 path with no node ip6")
						continue
					}
					if path.GetNeighborIp() == "<nil>" || path.GetNeighborIp() == "" { // Weird GoBGP API behaviour
						w.log.Debugf("Ignoring internal path")
						continue
					}
					if *config.GetCalicoVppFeatureGates().SRv6Enabled && path.GetFamily() == &common.BgpFamilySRv6IPv6 {
						w.log.Debugf("Path SRv6")
						err := w.injectSRv6Policy(path)
						if err != nil {
							w.log.Errorf("cannot inject SRv6: %v", err)
						}
						continue
					}
					w.log.Infof("Got path update from=%s as=%d family=%s", path.GetSourceId(), path.GetSourceAsn(), path.GetFamily())
					err := w.injectRoute(path)
					if err != nil {
						w.log.Errorf("cannot inject route: %v", err)
					}
				}
			}
		},
	)
	return stopFunc, err
}

func (w *BGPWatcher) NewBGPPolicyV4V6(CIDR string, matchOperator calicov3.BGPFilterMatchOperator, action calicov3.BGPFilterAction) (*bgpapi.DefinedSet, bgpapi.MatchSet_Type, bgpapi.RouteAction, string, error) {
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
func (w *BGPWatcher) addStatementToPolicy(pol *bgpapi.Policy, routeAction bgpapi.RouteAction, neighborName string, prefixName string, matchSetType bgpapi.MatchSet_Type) {
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

func (w *BGPWatcher) NewBGPPolicyAndAssignment(name string, rulesv4 []calicov3.BGPFilterRuleV4, rulesv6 []calicov3.BGPFilterRuleV6, neighborName string, dir bgpapi.PolicyDirection) (*BGPPrefixesPolicyAndAssignment, error) {
	pol := &bgpapi.Policy{Name: name}
	prefixes := []*bgpapi.DefinedSet{}
	for _, rule := range rulesv6 {
		defset, matchSetType, routeAction, prefixName, err := w.NewBGPPolicyV4V6(rule.CIDR, rule.MatchOperator, rule.Action)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, defset)
		w.addStatementToPolicy(pol, routeAction, neighborName, prefixName, matchSetType)
	}
	for _, rule := range rulesv4 {
		defset, matchSetType, routeAction, prefixName, err := w.NewBGPPolicyV4V6(rule.CIDR, rule.MatchOperator, rule.Action)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, defset)
		w.addStatementToPolicy(pol, routeAction, neighborName, prefixName, matchSetType)
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
func (w *BGPWatcher) filterPeer(peerAddress string, filterNames []string) (map[string]*ImpExpPol, error) {
	BGPPolicies := make(map[string]*ImpExpPol)
	if len(filterNames) != 0 {
		w.log.Infof("Peer: (neighbor=%s) has filters, applying filters %s ...", peerAddress, filterNames)
		for _, filterName := range filterNames {
			_, ok := w.bgpFilters[filterName]
			if !ok {
				w.log.Warnf("peer (neighbor=%s) uses filter %s that does not exist yet", peerAddress, filterName)
				// save state for late filter creation
				BGPPolicies[filterName] = nil
			} else {
				impExpPol, err := w.createFilterPolicy(peerAddress, filterName, peerAddress+"neighbor")
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
func (w *BGPWatcher) createFilterPolicy(peerAddress string, filterName string, neighborSet string) (*ImpExpPol, error) {
	w.log.Infof("Creating policies for: (peer: %s, filter: %s, neighborSet: %s)", peerAddress, filterName, neighborSet)
	filter := w.bgpFilters[filterName]
	imppol, err := w.NewBGPPolicyAndAssignment("import-"+peerAddress+"-"+filterName, filter.Spec.ImportV4, filter.Spec.ImportV6, neighborSet, bgpapi.PolicyDirection_IMPORT)
	if err != nil {
		return nil, err
	}
	exppol, err := w.NewBGPPolicyAndAssignment("export-"+peerAddress+"-"+filterName, filter.Spec.ExportV4, filter.Spec.ExportV6, neighborSet, bgpapi.PolicyDirection_EXPORT)
	if err != nil {
		return nil, err
	}
	for _, pol := range []*BGPPrefixesPolicyAndAssignment{imppol, exppol} {
		for _, defset := range pol.Prefixes {
			err := w.BGPServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{
				DefinedSet: defset,
			})
			if err != nil {
				return nil, err
			}
		}
		err = w.BGPServer.AddPolicy(context.Background(), &bgpapi.AddPolicyRequest{Policy: pol.Policy})
		if err != nil {
			return nil, errors.Wrapf(err, "error adding policy")
		}
		err = w.BGPServer.AddPolicyAssignment(context.Background(), &bgpapi.AddPolicyAssignmentRequest{Assignment: pol.PolicyAssignment})
		if err != nil {
			return nil, errors.Wrapf(err, "error adding policy assignment")
		}
	}
	return &ImpExpPol{Imp: imppol, Exp: exppol}, nil
}

// deleteFilterPolicy deletes policies and their assignments in gobgp
func (w *BGPWatcher) deleteFilterPolicy(impExpPol *ImpExpPol) error {
	for _, pol := range []*BGPPrefixesPolicyAndAssignment{impExpPol.Imp, impExpPol.Exp} {
		err := w.BGPServer.DeletePolicyAssignment(context.Background(), &bgpapi.DeletePolicyAssignmentRequest{Assignment: pol.PolicyAssignment})
		if err != nil {
			return errors.Wrapf(err, "error deleting policy assignment")
		}
		err = w.BGPServer.DeletePolicy(context.Background(), &bgpapi.DeletePolicyRequest{Policy: pol.Policy, All: true})
		if err != nil {
			return errors.Wrapf(err, "error deleting policy assignment")
		}
		for _, defset := range pol.Prefixes {
			err = w.BGPServer.DeleteDefinedSet(context.Background(), &bgpapi.DeleteDefinedSetRequest{DefinedSet: defset, All: true})
			if err != nil {
				return errors.Wrapf(err, "error deleting prefix set")
			}
		}
	}
	return nil
}

// cleanUpPeerFilters cleans up policies for a particular peer, from gobgp and saved state
func (w *BGPWatcher) cleanUpPeerFilters(peerAddr string) error {
	polToDelete := []string{}
	for name, impExpPol := range w.bgpPeers[peerAddr].BGPPolicies {
		w.log.Infof("deleting filter: %s", name)
		err := w.deleteFilterPolicy(impExpPol)
		if err != nil {
			return errors.Wrapf(err, "error deleting filter policies")
		}
		polToDelete = append(polToDelete, name)
	}
	for _, name := range polToDelete {
		delete(w.bgpPeers[peerAddr].BGPPolicies, name)
	}
	return nil
}

func (w *BGPWatcher) createEmptyPrefixSet(name string) error {
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        name,
	}
	err := w.BGPServer.AddDefinedSet(
		context.Background(),
		&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
	)
	if err != nil {
		return errors.Wrapf(err, "error creating prefix set %s", name)
	}
	return nil
}

// initialPolicySetting initialize BGP export policy.
// this creates two prefix-sets named 'aggregated' and 'host'.
// A route is allowed to be exported when it matches with 'aggregated' set,
// and not allowed when it matches with 'host' set.
func (w *BGPWatcher) initialPolicySetting(isv6 bool) error {
	aggregatedPrefixSetName := common.GetAggPrefixSetName(isv6)
	hostPrefixSetName := common.GetHostPrefixSetName(isv6)
	err := w.createEmptyPrefixSet(aggregatedPrefixSetName)
	if err != nil {
		return err
	}
	err = w.createEmptyPrefixSet(hostPrefixSetName)
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

	err = w.BGPServer.AddPolicy(
		context.Background(),
		&bgpapi.AddPolicyRequest{
			Policy:                  definition,
			ReferExistingStatements: false,
		},
	)
	if err != nil {
		return errors.Wrap(err, "error adding policy")
	}
	err = w.BGPServer.AddPolicyAssignment(
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

// WatchBGPPath watches BGP routes from other peers and inject them into linux kernel
// TODO: multipath support
func (w *BGPWatcher) WatchBGPPath(t *tomb.Tomb) error {
	stopBGPMonitoring, err := w.startBGPMonitoring()
	if err != nil {
		return errors.Wrap(err, "error starting BGP monitoring")
	}

	for {
		select {
		case <-t.Dying():
			stopBGPMonitoring()
			w.log.Infof("BGP Watcher asked to stop")
			return nil
		case msg := <-w.bgpWatcherEventChan:
			evt, ok := msg.(common.CalicoVppEvent)
			if !ok {
				continue
			}
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.BGPPathAdded:
				path, ok := evt.New.(*bgpapi.Path)
				if !ok {
					return fmt.Errorf("evt.New is not a (*bgpapi.Path) %v", evt.New)
				}
				_, err = w.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
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
				err = w.BGPServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
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
				err := w.BGPServer.AddDefinedSet(
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
				err := w.BGPServer.DeleteDefinedSet(
					context.Background(),
					&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
				)
				if err != nil {
					return err
				}
			case common.BGPPeerAdded:
				localPeer, ok := evt.New.(*LocalBGPPeer)
				if !ok {
					return fmt.Errorf("evt.New is not a (*LocalBGPPeer) %v", evt.New)
				}
				peer := localPeer.Peer
				filters := localPeer.BGPFilterNames
				// create a neighbor set to apply filter only on specific peer using a global policy
				neighborSet := &bgpapi.DefinedSet{
					Name:        peer.Conf.NeighborAddress + "neighbor",
					DefinedType: bgpapi.DefinedType_NEIGHBOR,
					List:        []string{peer.Conf.NeighborAddress + "/32"},
				}
				err := w.BGPServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{
					DefinedSet: neighborSet,
				})
				if err != nil {
					return errors.Wrapf(err, "error creating neighbor set")
				}
				BGPPolicies, err := w.filterPeer(peer.Conf.NeighborAddress, filters)
				if err != nil {
					return errors.Wrapf(err, "error filtering peer")
				}
				w.log.Infof("bgp(add) new neighbor=%s AS=%d",
					peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
				err = w.BGPServer.AddPeer(
					context.Background(),
					&bgpapi.AddPeerRequest{Peer: peer},
				)
				if err != nil {
					return err
				}
				localPeer.BGPPolicies = BGPPolicies
				localPeer.NeighborSet = neighborSet
				w.bgpPeers[peer.Conf.NeighborAddress] = localPeer
			case common.BGPPeerDeleted:
				addr, ok := evt.New.(string)
				if !ok {
					return fmt.Errorf("evt.New is not a (string) %v", evt.New)
				}
				w.log.Infof("bgp(del) neighbor=%s", addr)
				err = w.cleanUpPeerFilters(addr)
				if err != nil {
					return errors.Wrapf(err, "error cleaning peer filters up")
				}
				err = w.BGPServer.DeleteDefinedSet(context.Background(), &bgpapi.DeleteDefinedSetRequest{DefinedSet: w.bgpPeers[addr].NeighborSet, All: true})
				if err != nil {
					return errors.Wrapf(err, "error deleting prefix set")
				}
				err := w.BGPServer.DeletePeer(
					context.Background(),
					&bgpapi.DeletePeerRequest{Address: addr},
				)
				if err != nil {
					return err
				}
				delete(w.bgpPeers, addr)
			case common.BGPPeerUpdated:
				oldPeer, ok := evt.Old.(*LocalBGPPeer)
				if !ok {
					return fmt.Errorf("evt.Old is not (*LocalBGPPeer) %v", evt.Old)
				}
				localPeer, ok := evt.New.(*LocalBGPPeer)
				if !ok {
					return fmt.Errorf("evt.New is not (*LocalBGPPeer %v", evt.New)
				}
				peer := localPeer.Peer
				filters := localPeer.BGPFilterNames
				w.log.Infof("bgp(upd) neighbor=%s", peer.Conf.NeighborAddress)
				var BGPPolicies map[string]*ImpExpPol
				if !CompareStringSlices(localPeer.BGPFilterNames, oldPeer.BGPFilterNames) { // update filters
					err = w.cleanUpPeerFilters(peer.Conf.NeighborAddress)
					if err != nil {
						return errors.Wrapf(err, "error cleaning peer filters up")
					}
					BGPPolicies, err = w.filterPeer(peer.Conf.NeighborAddress, filters)
					if err != nil {
						return errors.Wrapf(err, "error filtering peer")
					}
				}
				w.log.Infof("bgp(upd) neighbor=%s AS=%d",
					peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
				_, err = w.BGPServer.UpdatePeer(
					context.Background(),
					&bgpapi.UpdatePeerRequest{Peer: peer},
				)
				if err != nil {
					return err
				}
				localPeer.BGPPolicies = BGPPolicies
				w.bgpPeers[peer.Conf.NeighborAddress] = localPeer
			case common.BGPFilterAddedOrUpdated:
				filter, ok := evt.New.(calicov3.BGPFilter)
				if !ok {
					return fmt.Errorf("evt.New is not (calicov3.BGPFilter) %v", evt.New)
				}
				w.log.Infof("bgp(add/upd) filter: %s", filter.Name)
				w.bgpFilters[filter.Name] = &filter
				// If this filter is already used in gobgp, delete old policies if any and recreate them
				for peerAddress := range w.bgpPeers {
					if impExpPol, ok := w.bgpPeers[peerAddress].BGPPolicies[filter.Name]; ok {
						w.log.Infof("filter used in %s, updating filter", peerAddress)
						if impExpPol != nil {
							err := w.deleteFilterPolicy(impExpPol)
							if err != nil {
								return errors.Wrap(err, "error deleting filter policies")
							}
						} // else we received peer using a filter before receiving the filter, so just create it
						impExpPol, err := w.createFilterPolicy(peerAddress, filter.Name, peerAddress+"neighbor")
						if err != nil {
							return errors.Wrap(err, "error creating filters")
						}
						w.bgpPeers[peerAddress].BGPPolicies[filter.Name] = impExpPol
						// have to update peers to apply changes
						_, err = w.BGPServer.UpdatePeer(
							context.Background(),
							&bgpapi.UpdatePeerRequest{Peer: w.bgpPeers[peerAddress].Peer},
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
				w.log.Infof("bgp(del) filter deleted: %s", filter.Name)
				delete(w.bgpFilters, filter.Name)
			}
		}
	}
}

func (w *BGPWatcher) ServeBGPWatcher(t *tomb.Tomb) (err error) {
	w.log.Infof("BGP Watcher started")

	for t.Alive() {
		globalConfig, err := w.getGoBGPGlobalConfig()
		if err != nil {
			return fmt.Errorf("cannot get global configuration: %v", err)
		}

		err = w.BGPServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{Global: globalConfig})
		if err != nil {
			return errors.Wrap(err, "failed to start BGP server")
		}

		nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
		if nodeIP4 != nil {
			err = w.initialPolicySetting(false /* isv6 */)
			if err != nil {
				return errors.Wrap(err, "error configuring initial policies")
			}
		}
		if nodeIP6 != nil {
			err = w.initialPolicySetting(true /* isv6 */)
			if err != nil {
				return errors.Wrap(err, "error configuring initial policies")
			}
		}

		w.log.Infof("BGP Watcher is running ")

		/* Start watching goBGP */
		err = w.WatchBGPPath(t)
		if err != nil {
			w.log.Error(err)
			return err
		}

		/* watch returned, we shall restart */
		err = w.BGPServer.StopBgp(context.Background(), &bgpapi.StopBgpRequest{})
		if err != nil {
			w.log.Errorf("failed to stop BGP server: %s", err)
		}
		w.log.Infof("BGP Watcher stopped")

	}
	w.log.Warn("BGP Watcher returned")

	return nil
}
