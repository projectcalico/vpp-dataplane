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

package routing

import (
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"golang.org/x/net/context"
)

func (s *Server) createEmptyPrefixSet(name string) error {
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        name,
	}
	err := s.BGPServer.AddDefinedSet(
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
	aggregatedPrefixSetName := common.GetAggPrefixSetName(isv6)
	hostPrefixSetName := common.GetHostPrefixSetName(isv6)
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
		Name: common.GetPolicyName(isv6),
		Statements: []*bgpapi.Statement{
			{
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
			{
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

	err = s.BGPServer.AddPolicy(
		context.Background(),
		&bgpapi.AddPolicyRequest{
			Policy:                  definition,
			ReferExistingStatements: false,
		},
	)
	if err != nil {
		return errors.Wrap(err, "error adding policy")
	}
	err = s.BGPServer.AddPolicyAssignment(
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

// Configure SNAT prefixes so that we don't snat traffic going from a local pod to the node
func (s *Server) configureLocalNodeSnat() error {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	if nodeIP4 != nil {
		err := s.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(*nodeIP4), true)
		if err != nil {
			return errors.Wrapf(err, "error configuring snat prefix for current node (%v)", *nodeIP4)
		}
	}
	if nodeIP6 != nil {
		err := s.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(*nodeIP6), true)
		if err != nil {
			return errors.Wrapf(err, "error configuring snat prefix for current node (%v)", *nodeIP6)
		}
	}
	return nil
}
