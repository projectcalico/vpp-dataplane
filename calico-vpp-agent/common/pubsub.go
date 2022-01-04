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
	OurNodeStateChanged  CalicoVppEventType = "OurNodeStateChanged"
	FelixConfChanged     CalicoVppEventType = "FelixConfChanged"
	IpamConfChanged      CalicoVppEventType = "IpamConfChanged"
	BGPConfChanged       CalicoVppEventType = "BGPConfChanged"

	ConnectivityAdded   CalicoVppEventType = "ConnectivityAdded"
	ConnectivityDeleted CalicoVppEventType = "ConnectivityDeleted"

	PodAdded   CalicoVppEventType = "PodAdded"
	PodDeleted CalicoVppEventType = "PodDeleted"

	LocalPodAddressAdded   CalicoVppEventType = "LocalPodAddressAdded"
	LocalPodAddressDeleted CalicoVppEventType = "LocalPodAddressDeleted"

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
)

var (
	ThePubSub *PubSub
)

type CalicoVppEvent struct {
	Type CalicoVppEventType

	Old interface{}
	New interface{}
}

type PubSub struct {
	log         *logrus.Entry
	pubSubChans []chan CalicoVppEvent
}

func RegisterHandler(c chan CalicoVppEvent) {
	ThePubSub.pubSubChans = append(ThePubSub.pubSubChans, c)
}

func SendEvent(e CalicoVppEvent) {
	for _, c := range ThePubSub.pubSubChans {
		c <- e
	}
}

func NewPubSub(log *logrus.Entry) *PubSub {
	return &PubSub{
		log:         log,
		pubSubChans: make([]chan CalicoVppEvent, 0),
	}
}
