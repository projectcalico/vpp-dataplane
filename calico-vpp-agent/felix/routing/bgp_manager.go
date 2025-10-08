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

package routing

import (
	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// BGPManager coordinates the BGP watcher and routing handler without pubsub
type BGPManager struct {
	log            *logrus.Entry
	bgpWatcher     *watchers.BGPWatcher
	routingHandler *RoutingHandler
	bgpHandler     *BGPHandler
}

// NewBGPManager creates a fully integrated BGP manager
func NewBGPManager(bgpServer *bgpserver.BgpServer, vpp *vpplink.VppLink, felixEventChan chan any, log *logrus.Entry) *BGPManager {
	// Create bgpWatcher
	bgpWatcher := watchers.NewBGPWatcher(bgpServer, log.WithFields(logrus.Fields{"component": "bgp-watcher"}))

	// Create bgpHandler
	bgpHandler := NewBGPHandler(bgpServer, log.WithFields(logrus.Fields{"component": "bgp-handler"}))

	// Create routingHandler
	routingHandler := NewRoutingHandler(vpp, felixEventChan, log.WithFields(logrus.Fields{"component": "routing-handler"}))

	// Create BGPManager
	bgpManager := &BGPManager{
		log:            log,
		bgpWatcher:     bgpWatcher,
		routingHandler: routingHandler,
		bgpHandler:     bgpHandler,
	}

	// Set up connections
	bgpWatcher.SetBGPHandler(bgpHandler)
	bgpHandler.SetBGPConnectivityHandler(bgpManager)
	routingHandler.SetBGPPathHandler(bgpManager)

	return bgpManager
}

// SetBGPConf sets BGP configuration on both components
func (m *BGPManager) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	m.bgpWatcher.SetBGPConf(bgpConf)
	m.routingHandler.SetBGPConf(bgpConf)
}

// SetOurBGPSpec sets BGP spec on both components
func (m *BGPManager) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	m.bgpWatcher.SetOurBGPSpec(nodeBGPSpec)
	m.routingHandler.SetOurBGPSpec(nodeBGPSpec)
}

// StartBGPWatcher starts the BGP watcher component
func (m *BGPManager) StartBGPWatcher(t *tomb.Tomb) error {
	m.log.Info("Starting BGP watcher via BGP manager")
	return m.bgpWatcher.WatchBGPPath(t)
}

// StartRoutingHandler starts the routing handler component
func (m *BGPManager) StartRoutingHandler(t *tomb.Tomb) error {
	m.log.Info("Starting routing handler via BGP manager")
	return m.routingHandler.ServeRoutingHandler(t)
}

// BGPConnectivityHandler methods - routes events from BGP watcher to routing handler
func (m *BGPManager) OnConnectivityAdded(connectivity *common.NodeConnectivity) error {
	return m.routingHandler.HandleConnectivityAdded(connectivity)
}

func (m *BGPManager) OnConnectivityDeleted(connectivity *common.NodeConnectivity) error {
	return m.routingHandler.HandleConnectivityDeleted(connectivity)
}

func (m *BGPManager) OnSRv6PolicyAdded(connectivity *common.NodeConnectivity) error {
	return m.routingHandler.HandleSRv6PolicyAdded(connectivity)
}

func (m *BGPManager) OnSRv6PolicyDeleted(connectivity *common.NodeConnectivity) error {
	return m.routingHandler.HandleSRv6PolicyDeleted(connectivity)
}

// BGP path management methods
func (m *BGPManager) HandleBGPPathAdded(path *bgpapi.Path) error {
	return m.bgpHandler.HandleBGPPathAdded(path)
}

func (m *BGPManager) HandleBGPPathDeleted(path *bgpapi.Path) error {
	return m.bgpHandler.HandleBGPPathDeleted(path)
}

// BGP peer management methods
func (m *BGPManager) HandleBGPPeerAdded(localPeer *common.LocalBGPPeer) error {
	return m.bgpHandler.HandleBGPPeerAdded(localPeer)
}

func (m *BGPManager) HandleBGPPeerUpdated(localPeer *common.LocalBGPPeer, oldPeer *common.LocalBGPPeer) error {
	return m.bgpHandler.HandleBGPPeerUpdated(localPeer, oldPeer)
}

func (m *BGPManager) HandleBGPPeerDeleted(peerIP string) error {
	return m.bgpHandler.HandleBGPPeerDeleted(peerIP)
}

// BGP filter management methods
func (m *BGPManager) HandleBGPFilterAddedOrUpdated(filter calicov3.BGPFilter) error {
	return m.bgpHandler.HandleBGPFilterAddedOrUpdated(filter)
}

func (m *BGPManager) HandleBGPFilterDeleted(filter calicov3.BGPFilter) error {
	return m.bgpHandler.HandleBGPFilterDeleted(filter)
}

// BGP defined set management methods
func (m *BGPManager) HandleBGPDefinedSetAdded(definedSet *bgpapi.DefinedSet) error {
	return m.bgpHandler.HandleBGPDefinedSetAdded(definedSet)
}

func (m *BGPManager) HandleBGPDefinedSetDeleted(definedSet *bgpapi.DefinedSet) error {
	return m.bgpHandler.HandleBGPDefinedSetDeleted(definedSet)
}
