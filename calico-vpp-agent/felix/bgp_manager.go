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

package felix

import (
	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/routing"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// BGPPathHandler interface for handling BGP path events from routing handler
type BGPPathHandler interface {
	OnBGPPathAdded(path *bgpapi.Path) error
	OnBGPPathDeleted(path *bgpapi.Path) error
}

// ConnectivityHandler interface for handling connectivity events from BGP watcher
type ConnectivityHandler interface {
	OnConnectivityAdded(connectivity *common.NodeConnectivity) error
	OnConnectivityDeleted(connectivity *common.NodeConnectivity) error
	OnSRv6PolicyAdded(connectivity *common.NodeConnectivity) error
	OnSRv6PolicyDeleted(connectivity *common.NodeConnectivity) error
}

// BGPManager coordinates the BGP watcher and routing handler without pubsub
type BGPManager struct {
	log            *logrus.Entry
	bgpWatcher     *watchers.BGPWatcher
	routingHandler *routing.RoutingHandler
}

// NewBGPManager creates a fully integrated BGP manager
func NewBGPManager(bgpServer *bgpserver.BgpServer, vpp *vpplink.VppLink, felixEventChan chan any, log *logrus.Entry) *BGPManager {
	// Create BGP watcher
	bgpWatcher := watchers.NewBGPWatcher(bgpServer, log.WithFields(logrus.Fields{"component": "bgp-watcher"}))

	// Create routing handler
	routingHandler := routing.NewRoutingHandler(vpp, felixEventChan, log.WithFields(logrus.Fields{"component": "routing-handler"}))

	manager := &BGPManager{
		log:            log,
		bgpWatcher:     bgpWatcher,
		routingHandler: routingHandler,
	}

	// Set up direct communication - BGP manager acts as the intermediary
	bgpWatcher.SetConnectivityHandler(manager)
	routingHandler.SetBGPPathHandler(manager)

	return manager
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

// BGPPathHandler implementation - routes events from routing handler to BGP watcher
func (m *BGPManager) OnBGPPathAdded(path *bgpapi.Path) error {
	m.log.Debugf("BGP manager forwarding BGP path added event")
	return m.bgpWatcher.HandleBGPPathAdded(path)
}

func (m *BGPManager) OnBGPPathDeleted(path *bgpapi.Path) error {
	m.log.Debugf("BGP manager forwarding BGP path deleted event")
	return m.bgpWatcher.HandleBGPPathDeleted(path)
}

// ConnectivityHandler implementation - routes events from BGP watcher to routing handler
func (m *BGPManager) OnConnectivityAdded(connectivity *common.NodeConnectivity) error {
	m.log.Debugf("BGP manager forwarding connectivity added event")
	return m.routingHandler.HandleConnectivityAdded(connectivity)
}

func (m *BGPManager) OnConnectivityDeleted(connectivity *common.NodeConnectivity) error {
	m.log.Debugf("BGP manager forwarding connectivity deleted event")
	return m.routingHandler.HandleConnectivityDeleted(connectivity)
}

func (m *BGPManager) OnSRv6PolicyAdded(connectivity *common.NodeConnectivity) error {
	m.log.Debugf("BGP manager forwarding SRv6 policy added event")
	return m.routingHandler.HandleSRv6PolicyAdded(connectivity)
}

func (m *BGPManager) OnSRv6PolicyDeleted(connectivity *common.NodeConnectivity) error {
	m.log.Debugf("BGP manager forwarding SRv6 policy deleted event")
	return m.routingHandler.HandleSRv6PolicyDeleted(connectivity)
}

// BGP peer management methods
func (m *BGPManager) HandleBGPPeerAdded(localPeer *watchers.LocalBGPPeer) error {
	m.log.Debugf("BGP manager handling BGP peer added")
	return m.bgpWatcher.HandleBGPPeerAdded(localPeer)
}

func (m *BGPManager) HandleBGPPeerUpdated(localPeer *watchers.LocalBGPPeer, oldPeer *watchers.LocalBGPPeer) error {
	m.log.Debugf("BGP manager handling BGP peer updated")
	return m.bgpWatcher.HandleBGPPeerUpdated(localPeer, oldPeer)
}

func (m *BGPManager) HandleBGPPeerDeleted(peerIP string) error {
	m.log.Debugf("BGP manager handling BGP peer deleted")
	return m.bgpWatcher.HandleBGPPeerDeleted(peerIP)
}

// BGP filter management methods
func (m *BGPManager) HandleBGPFilterAddedOrUpdated(filter calicov3.BGPFilter) error {
	m.log.Debugf("BGP manager handling BGP filter added/updated")
	return m.bgpWatcher.HandleBGPFilterAddedOrUpdated(filter)
}

func (m *BGPManager) HandleBGPFilterDeleted(filter calicov3.BGPFilter) error {
	m.log.Debugf("BGP manager handling BGP filter deleted")
	return m.bgpWatcher.HandleBGPFilterDeleted(filter)
}

// BGP defined set management methods
func (m *BGPManager) HandleBGPDefinedSetAdded(definedSet *bgpapi.DefinedSet) error {
	m.log.Debugf("BGP manager handling BGP defined set added")
	return m.bgpWatcher.HandleBGPDefinedSetAdded(definedSet)
}

func (m *BGPManager) HandleBGPDefinedSetDeleted(definedSet *bgpapi.DefinedSet) error {
	m.log.Debugf("BGP manager handling BGP defined set deleted")
	return m.bgpWatcher.HandleBGPDefinedSetDeleted(definedSet)
}
