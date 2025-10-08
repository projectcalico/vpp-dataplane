// Copyright (C) 2025 Cisco Systems Inc.
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

package common

import (
	bgpapi "github.com/osrg/gobgp/v3/api"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
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

// BGPConnectivityHandler interface for handling connectivity events
type BGPConnectivityHandler interface {
	OnConnectivityAdded(connectivity *NodeConnectivity) error
	OnConnectivityDeleted(connectivity *NodeConnectivity) error
	OnSRv6PolicyAdded(connectivity *NodeConnectivity) error
	OnSRv6PolicyDeleted(connectivity *NodeConnectivity) error
}

// BGPPathHandler interface for handling BGP path operations
type BGPPathHandler interface {
	HandleBGPPathAdded(path *bgpapi.Path) error
	HandleBGPPathDeleted(path *bgpapi.Path) error
}

// BGPPeerHandler interface for handling BGP peer operations
type BGPPeerHandler interface {
	HandleBGPPeerAdded(localPeer *LocalBGPPeer) error
	HandleBGPPeerUpdated(localPeer *LocalBGPPeer, oldPeer *LocalBGPPeer) error
	HandleBGPPeerDeleted(peerIP string) error
}

// BGPFilterHandler interface for handling BGP filter operations
type BGPFilterHandler interface {
	HandleBGPFilterAddedOrUpdated(filter calicov3.BGPFilter) error
	HandleBGPFilterDeleted(filter calicov3.BGPFilter) error
}

// BGPDefinedSetHandler interface for handling BGP defined set operations
type BGPDefinedSetHandler interface {
	HandleBGPDefinedSetAdded(definedSet *bgpapi.DefinedSet) error
	HandleBGPDefinedSetDeleted(definedSet *bgpapi.DefinedSet) error
}

// BGPHandler interface for handling different BGP operations
type BGPHandler interface {
	BGPPathHandler
	BGPPeerHandler
	BGPFilterHandler
	BGPDefinedSetHandler

	SetBGPConnectivityHandler(handler BGPConnectivityHandler)
	InjectRoute(path *bgpapi.Path) error
	InjectSRv6Policy(path *bgpapi.Path) error
	InitialPolicySetting(isv6 bool) error
}
