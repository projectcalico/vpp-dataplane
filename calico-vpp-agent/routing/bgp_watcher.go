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
	"fmt"
	"net"

	"github.com/golang/protobuf/ptypes"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/connectivity"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"golang.org/x/net/context"
)

func isCrossSubnet(gw net.IP, subnet net.IPNet) bool {
	return !subnet.Contains(gw)
}

func (s *Server) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := ptypes.UnmarshalAny(attr, nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := ptypes.UnmarshalAny(attr, mpReachAttr); err == nil {
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
	otherNodeIP := net.ParseIP(s.getNexthop(path))
	if otherNodeIP == nil {
		return fmt.Errorf("Cannot determine path nexthop: %+v", path)
	}

	if err := ptypes.UnmarshalAny(path.Nlri, ipAddrPrefixNlri); err == nil {
		dst.IP = net.ParseIP(ipAddrPrefixNlri.Prefix)
		if dst.IP == nil {
			return fmt.Errorf("Cannot parse nlri addr: %s", ipAddrPrefixNlri.Prefix)
		} else if dst.IP.To4() == nil {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 128)
		} else {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 32)
		}
	} else {
		return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}

	cn := &connectivity.NodeConnectivity{
		Dst:     dst,
		NextHop: otherNodeIP,
	}
	err := s.updateIPConnectivity(cn, path.IsWithdraw)
	return err
}

func (s *Server) getProviderType(cn *connectivity.NodeConnectivity) string {
	ipPool := s.ipam.GetPrefixIPPool(&cn.Dst)
	if ipPool == nil {
		return connectivity.FLAT
	}
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeAlways {
		if s.providers[connectivity.IPSEC].Enabled() {
			return connectivity.IPSEC
		} else if s.providers[connectivity.WIREGUARD].Enabled() {
			return connectivity.WIREGUARD
		} else {
			return connectivity.IPIP
		}
	}
	ipNet := s.GetNodeIPNet(vpplink.IsIP6(cn.Dst.IP))
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeCrossSubnet && !isCrossSubnet(cn.NextHop, *ipNet) {
		if s.providers[connectivity.IPSEC].Enabled() {
			return connectivity.IPSEC
		} else if s.providers[connectivity.WIREGUARD].Enabled() {
			return connectivity.WIREGUARD
		} else {
			return connectivity.IPIP
		}
	}
	if ipPool.Spec.VXLANMode == calicov3.VXLANModeAlways {
		return connectivity.VXLAN
	}
	if ipPool.Spec.VXLANMode == calicov3.VXLANModeCrossSubnet && !isCrossSubnet(cn.NextHop, *ipNet) {
		return connectivity.VXLAN
	}
	return connectivity.FLAT
}

func (s *Server) updateAllIPConnectivityMonitor() error {
	for {
		_ = <-s.updateAllIPConnectivityChan
		s.log.Infof("Felix config changed, re-updating connectivity")
		for _, cn := range s.connectivityMap {
			s.log.Infof("Felix config changed %s", cn)
			err := s.updateIPConnectivity(&cn, false /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while re-updating connectivity %s", err)
			}
		}
	}
	return nil
}

func (s *Server) updateAllIPConnectivity() {
	/* ping the bgp watcher as caller might share lock */
	s.updateAllIPConnectivityChan <- true
}

func (s *Server) updateIPConnectivity(cn *connectivity.NodeConnectivity, IsWithdraw bool) (err error) {
	s.updateIPConnectivityLock.Lock()
	defer s.updateIPConnectivityLock.Unlock()
	var providerType string
	if IsWithdraw {
		oldCn, found := s.connectivityMap[cn.String()]
		if !found {
			providerType = s.getProviderType(cn)
			s.log.Infof("Didnt find provider in map, trying :%s", providerType)
		} else {
			providerType = oldCn.ResolvedProvider
			delete(s.connectivityMap, oldCn.String())
			s.log.Infof("Deleting path (%s) %s", providerType, oldCn.String())
		}
		return s.providers[providerType].DelConnectivity(cn)
	} else {
		providerType = s.getProviderType(cn)
		oldCn, found := s.connectivityMap[cn.String()]
		if found {
			oldProviderType := oldCn.ResolvedProvider
			if oldProviderType != providerType {
				s.log.Infof("Path (%s) changed provider (%s->%s) %s", providerType, oldProviderType, providerType, cn.String())
				err := s.providers[oldProviderType].DelConnectivity(cn)
				if err != nil {
					s.log.Errorf("Error del connectivity when changing provider %s->%s : %s", oldProviderType, providerType, err)
				}
				cn.ResolvedProvider = providerType
				s.connectivityMap[cn.String()] = *cn
				return s.providers[providerType].AddConnectivity(cn)
			} else {
				s.log.Infof("Added same path (%s) %s", providerType, cn.String())
				return s.providers[providerType].AddConnectivity(cn)
			}
		} else {
			s.log.Infof("Added path (%s) %s", providerType, cn.String())
			cn.ResolvedProvider = providerType
			s.connectivityMap[cn.String()] = *cn
			return s.providers[providerType].AddConnectivity(cn)
		}
	}
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (s *Server) watchBGPPath() error {
	var err error
	startMonitor := func(f *bgpapi.Family) (context.CancelFunc, error) {
		ctx, stopFunc := context.WithCancel(context.Background())
		err := s.bgpServer.MonitorTable(
			ctx,
			&bgpapi.MonitorTableRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Name:      "",
				Family:    f,
				Current:   false,
			},
			func(path *bgpapi.Path) {
				if path == nil {
					s.log.Warnf("nil path update, skipping")
					return
				}
				s.log.Infof("Got path update from %s as %d", path.SourceId, path.SourceAsn)
				if path.NeighborIp == "<nil>" { // Weird GoBGP API behaviour
					s.log.Debugf("Ignoring internal path")
					return
				}
				s.BarrierSync()
				if err := s.injectRoute(path); err != nil {
					s.log.Errorf("cannot inject route: %v", err)
				}
			},
		)
		return stopFunc, err
	}

	var stopV4Monitor, stopV6Monitor context.CancelFunc
	if s.hasV4 {
		stopV4Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
		if err != nil {
			return errors.Wrap(err, "error starting v4 path monitor")
		}
	}
	if s.hasV6 {
		stopV6Monitor, err = startMonitor(&bgpFamilyUnicastIPv6)
		if err != nil {
			return errors.Wrap(err, "error starting v6 path monitor")
		}
	}
	for family := range s.reloadCh {
		if s.hasV4 && family == "4" {
			stopV4Monitor()
			stopV4Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
			if err != nil {
				return err
			}
		} else if s.hasV6 && family == "6" {
			stopV6Monitor()
			stopV6Monitor, err = startMonitor(&bgpFamilyUnicastIPv6)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) createEmptyPrefixSet(name string) error {
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        name,
	}
	err := s.bgpServer.AddDefinedSet(
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
func (s *Server) initialPolicySetting(isv6 bool) error {
	aggregatedPrefixSetName := GetAggPrefixSetName(isv6)
	hostPrefixSetName := GetHostPrefixSetName(isv6)
	err := s.createEmptyPrefixSet(aggregatedPrefixSetName)
	if err != nil {
		return err
	}
	err = s.createEmptyPrefixSet(hostPrefixSetName)
	if err != nil {
		return err
	}
	// intended to work as same as 'calico_pools' export filter of BIRD configuration
	definition := &bgpapi.Policy{
		Name: GetPolicyName(isv6),
		Statements: []*bgpapi.Statement{
			&bgpapi.Statement{
				Conditions: &bgpapi.Conditions{
					PrefixSet: &bgpapi.MatchSet{
						MatchType: bgpapi.MatchType_ANY,
						Name:      aggregatedPrefixSetName,
					},
				},
				Actions: &bgpapi.Actions{
					RouteAction: bgpapi.RouteAction_ACCEPT,
				},
			},
			&bgpapi.Statement{
				Conditions: &bgpapi.Conditions{
					PrefixSet: &bgpapi.MatchSet{
						MatchType: bgpapi.MatchType_ANY,
						Name:      hostPrefixSetName,
					},
				},
				Actions: &bgpapi.Actions{
					RouteAction: bgpapi.RouteAction_REJECT,
				},
			},
		},
	}

	err = s.bgpServer.AddPolicy(
		context.Background(),
		&bgpapi.AddPolicyRequest{
			Policy:                  definition,
			ReferExistingStatements: false,
		},
	)
	if err != nil {
		return errors.Wrap(err, "error adding policy")
	}
	err = s.bgpServer.AddPolicyAssignment(
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
