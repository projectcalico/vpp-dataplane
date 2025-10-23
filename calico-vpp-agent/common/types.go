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
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type VRF struct {
	Tables [2]uint32 // one for ipv4, one for ipv6
}

type NetworkDefinition struct {
	// VRF is the main table used for the corresponding physical network
	VRF VRF
	// PodVRF is the table used for the pods in the corresponding physical network
	PodVRF              VRF
	Vni                 uint32
	PhysicalNetworkName string
	Name                string
	Range               string
	NetAttachDefs       string
}

// FelixSocketSyncState describes the status of the
// felix socket connection. It applies mostly to policies
type FelixSocketSyncState int

const (
	StateDisconnected FelixSocketSyncState = iota
	StateConnected
	StateSyncing
	StateInSync
)

func (state FelixSocketSyncState) IsPending() bool {
	return state != StateInSync
}

// FelixSocketStateChanged is emitted when the state
// of the socket changed. Typically connection and disconnection.
type FelixSocketStateChanged struct {
	NewState FelixSocketSyncState
}

type ServiceAndEndpoints struct {
	Service   *v1.Service
	Endpoints *v1.Endpoints
}

type ServiceEndpointsUpdate struct {
	New *ServiceAndEndpoints
	Old *ServiceAndEndpoints
}

type ServiceEndpointsDelete struct {
	Meta *metav1.ObjectMeta
}

// PeersChangedEvent is emitted when the list of BGP peers changes
type PeersChangedEvent struct {
	Peers []calicov3.BGPPeer
}

// PeerAddedEvent is emitted when a BGP peer is added
type PeerAddedEvent struct {
	Peer calicov3.BGPPeer
}

// PeerUpdatedEvent is emitted when a BGP peer is updated
type PeerUpdatedEvent struct {
	Old calicov3.BGPPeer
	New calicov3.BGPPeer
}

// PeerDeletedEvent is emitted when a BGP peer is deleted
type PeerDeletedEvent struct {
	Peer calicov3.BGPPeer
}

// SecretData represents secret information
type SecretData struct {
	Name string
	Data map[string][]byte
}

// SecretAddedEvent is emitted when a secret is added
type SecretAddedEvent struct {
	Secret *SecretData
}

// SecretChangedEvent is emitted when a secret changes
type SecretChangedEvent struct {
	SecretName string
}

// SecretDeletedEvent is emitted when a secret is deleted
type SecretDeletedEvent struct {
	SecretName string
}
