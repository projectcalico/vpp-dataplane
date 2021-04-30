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
	"fmt"
	"net"

	bgpapi "github.com/osrg/gobgp/api"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/options"
	commonAgent "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func (s *Server) createEmptyPrefixSet(name string) error {
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        name,
	}
	err := s.routingData.BGPServer.AddDefinedSet(
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

	err = s.routingData.BGPServer.AddPolicy(
		context.Background(),
		&bgpapi.AddPolicyRequest{
			Policy:                  definition,
			ReferExistingStatements: false,
		},
	)
	if err != nil {
		return errors.Wrap(err, "error adding policy")
	}
	err = s.routingData.BGPServer.AddPolicyAssignment(
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
	if s.routingData.HasV4 {
		err := s.routingData.Vpp.CnatAddDelSnatPrefix(commonAgent.ToMaxLenCIDR(s.routingData.Ipv4), true)
		if err != nil {
			return errors.Wrapf(err, "error configuring snat prefix for current node (%v)", s.routingData.Ipv4)
		}
	}
	if s.routingData.HasV6 {
		err := s.routingData.Vpp.CnatAddDelSnatPrefix(commonAgent.ToMaxLenCIDR(s.routingData.Ipv6), true)
		if err != nil {
			return errors.Wrapf(err, "error configuring snat prefix for current node (%v)", s.routingData.Ipv6)
		}
	}
	return nil
}

func (s *Server) fetchNodeIPs() (node *calicov3.Node, err error) {
	node, err = s.routingData.Clientv3.Nodes().Get(
		context.Background(),
		config.NodeName,
		options.GetOptions{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch current node")
	}

	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("Calico is running in policy-only mode")
	}
	s.routingData.Ipv4, s.routingData.Ipv4Net, err = net.ParseCIDR(node.Spec.BGP.IPv4Address)
	s.routingData.HasV4 = (err == nil)
	s.routingData.Ipv6, s.routingData.Ipv6Net, err = net.ParseCIDR(node.Spec.BGP.IPv6Address)
	s.routingData.HasV6 = (err == nil)
	s.log.Infof("Fetched node IPs v4:%s, v6:%s", s.routingData.Ipv4.String(), s.routingData.Ipv6.String())
	return node, nil
}

func (s *Server) createAndStartBGP() error {
	globalConfig, err := s.getGlobalConfig()
	if err != nil {
		return fmt.Errorf("cannot get global configuration: %v", err)
	}
	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxSize),
		grpc.MaxSendMsgSize(maxSize),
	}
	s.bgpServerRunningCond.L.Lock()
	s.routingData.BGPServer = bgpserver.NewBgpServer(
		bgpserver.GrpcListenAddress("localhost:50051"),
		bgpserver.GrpcOption(grpcOpts),
	)
	s.bgpServerRunningCond.L.Unlock()
	s.bgpServerRunningCond.Broadcast()

	s.t.Go(func() error { s.routingData.BGPServer.Serve(); return fmt.Errorf("bgpServer Serve returned") })

	return s.routingData.BGPServer.StartBgp(
		context.Background(),
		&bgpapi.StartBgpRequest{Global: globalConfig},
	)
}
