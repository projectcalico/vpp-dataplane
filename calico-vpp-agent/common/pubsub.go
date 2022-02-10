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

package common

import (
	"github.com/sirupsen/logrus"
)

type CalicoVppEventType string

const (
	ChanSize = 500

	PeerNodeStateChanged CalicoVppEventType = "PeerNodeStateChanged"
	FelixConfChanged     CalicoVppEventType = "FelixConfChanged"
	IpamConfChanged      CalicoVppEventType = "IpamConfChanged"
	BGPConfChanged       CalicoVppEventType = "BGPConfChanged"

	ConnectivityAdded   CalicoVppEventType = "ConnectivityAdded"
	ConnectivityDeleted CalicoVppEventType = "ConnectivityDeleted"

	SRv6PolicyAdded   CalicoVppEventType = "SRv6PolicyAdded"
	SRv6PolicyDeleted CalicoVppEventType = "SRv6PolicyDeleted"

	PodAdded   CalicoVppEventType = "PodAdded"
	PodDeleted CalicoVppEventType = "PodDeleted"

	LocalPodAddressAdded          CalicoVppEventType = "LocalPodAddressAdded"
	LocalPodAddressDeleted        CalicoVppEventType = "LocalPodAddressDeleted"
	LocalNetworkPodAddressAdded   CalicoVppEventType = "LocalNetworkPodAddressAdded"
	LocalNetworkPodAddressDeleted CalicoVppEventType = "LocalNetworkPodAddressDeleted"

	TunnelAdded   CalicoVppEventType = "TunnelAdded"
	TunnelDeleted CalicoVppEventType = "TunnelDeleted"

	BGPPeerAdded   CalicoVppEventType = "BGPPeerAdded"
	BGPPeerDeleted CalicoVppEventType = "BGPPeerDeleted"
	BGPPeerUpdated CalicoVppEventType = "BGPPeerUpdated"

	BGPDefinedSetAdded   CalicoVppEventType = "BGPDefinedSetAdded"
	BGPDefinedSetDeleted CalicoVppEventType = "BGPDefinedSetDeleted"

	BGPPathAdded   CalicoVppEventType = "BGPPathAdded"
	BGPPathDeleted CalicoVppEventType = "BGPPathDeleted"

	BGPReloadIP4 CalicoVppEventType = "BGPReloadIP4"
	BGPReloadIP6 CalicoVppEventType = "BGPReloadIP6"

	NetAdded   CalicoVppEventType = "NetAdded"
	NetUpdated CalicoVppEventType = "NetUpdated"
	NetDeleted CalicoVppEventType = "NetDeleted"
)

var (
	ThePubSub *PubSub
)

type CalicoVppEvent struct {
	Type CalicoVppEventType

	Old interface{}
	New interface{}
}

type PubSubHandlerRegistration struct {
	/* Name for the registration, for logging & debugging */
	name string
	/* Channel where to send events */
	channel chan CalicoVppEvent
	/* Receive only these events. If empty we'll receive all */
	expectedEvents map[CalicoVppEventType]bool
	/* Receive all events */
	expectAllEvents bool
}

func (reg *PubSubHandlerRegistration) ExpectEvents(eventTypes ...CalicoVppEventType) {
	for _, eventType := range eventTypes {
		reg.expectedEvents[eventType] = true
	}
	reg.expectAllEvents = false
}

type PubSub struct {
	log                        *logrus.Entry
	pubSubHandlerRegistrations []*PubSubHandlerRegistration
}

func RegisterHandler(channel chan CalicoVppEvent, name string) *PubSubHandlerRegistration {
	reg := &PubSubHandlerRegistration{
		channel:         channel,
		name:            name,
		expectedEvents:  make(map[CalicoVppEventType]bool),
		expectAllEvents: true, /* By default receive everything, unless we ask for a filter */
	}
	ThePubSub.pubSubHandlerRegistrations = append(ThePubSub.pubSubHandlerRegistrations, reg)
	return reg
}

func SendEvent(event CalicoVppEvent) {
	for _, reg := range ThePubSub.pubSubHandlerRegistrations {
		if reg.expectAllEvents || reg.expectedEvents[event.Type] {
			reg.channel <- event
		}
	}
}

func NewPubSub(log *logrus.Entry) *PubSub {
	return &PubSub{
		log:                        log,
		pubSubHandlerRegistrations: make([]*PubSubHandlerRegistration, 0),
	}
}
