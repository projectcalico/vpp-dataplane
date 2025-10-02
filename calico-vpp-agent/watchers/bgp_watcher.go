// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package watchers

import (
	"context"
	"fmt"

	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	logrus "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

// ConnectivityHandler interface for handling connectivity events
type ConnectivityHandler interface {
	OnConnectivityAdded(connectivity *common.NodeConnectivity) error
	OnConnectivityDeleted(connectivity *common.NodeConnectivity) error
	OnSRv6PolicyAdded(connectivity *common.NodeConnectivity) error
	OnSRv6PolicyDeleted(connectivity *common.NodeConnectivity) error
}

type BGPWatcher struct {
	log *logrus.Entry

	BGPConf     *calicov3.BGPConfigurationSpec
	BGPServer   *bgpserver.BgpServer
	nodeBGPSpec *common.LocalNodeSpec
	bgpHandler  *BGPHandler

	connectivityHandler ConnectivityHandler
}

func NewBGPWatcher(bgpServer *bgpserver.BgpServer, log *logrus.Entry) *BGPWatcher {
	bgpHandler := NewBGPHandler(bgpServer, log)
	watcher := &BGPWatcher{
		log:        log,
		BGPServer:  bgpServer,
		bgpHandler: bgpHandler,
	}

	return watcher
}

func (w *BGPWatcher) SetConnectivityHandler(handler ConnectivityHandler) {
	w.connectivityHandler = handler
	w.bgpHandler.SetConnectivityHandler(handler)
}

// HandleBGPPathAdded handles BGP path addition from routing handler
func (w *BGPWatcher) HandleBGPPathAdded(path *bgpapi.Path) error {
	w.log.Debugf("BGP watcher delegating BGP path added to handler")
	return w.bgpHandler.HandleBGPPathAdded(path)
}

// HandleBGPPathDeleted handles BGP path deletion from routing handler
func (w *BGPWatcher) HandleBGPPathDeleted(path *bgpapi.Path) error {
	w.log.Debugf("BGP watcher delegating BGP path deleted to handler")
	return w.bgpHandler.HandleBGPPathDeleted(path)
}

// HandleBGPPeerAdded handles BGP peer addition directly
func (w *BGPWatcher) HandleBGPPeerAdded(localPeer *LocalBGPPeer) error {
	w.log.Debugf("BGP watcher delegating BGP peer added to handler")
	return w.bgpHandler.HandleBGPPeerAdded(localPeer)
}

// HandleBGPPeerUpdated handles BGP peer updates directly
func (w *BGPWatcher) HandleBGPPeerUpdated(localPeer *LocalBGPPeer, oldPeer *LocalBGPPeer) error {
	w.log.Debugf("BGP watcher delegating BGP peer updated to handler")
	return w.bgpHandler.HandleBGPPeerUpdated(localPeer, oldPeer)
}

// HandleBGPPeerDeleted handles BGP peer deletion directly
func (w *BGPWatcher) HandleBGPPeerDeleted(peerIP string) error {
	w.log.Debugf("BGP watcher delegating BGP peer deleted to handler")
	return w.bgpHandler.HandleBGPPeerDeleted(peerIP)
}

// HandleBGPFilterAddedOrUpdated handles BGP filter addition or update directly
func (w *BGPWatcher) HandleBGPFilterAddedOrUpdated(filter calicov3.BGPFilter) error {
	w.log.Debugf("BGP watcher delegating BGP filter added/updated to handler")
	return w.bgpHandler.HandleBGPFilterAddedOrUpdated(filter)
}

// HandleBGPFilterDeleted handles BGP filter deletion directly
func (w *BGPWatcher) HandleBGPFilterDeleted(filter calicov3.BGPFilter) error {
	w.log.Debugf("BGP watcher delegating BGP filter deleted to handler")
	return w.bgpHandler.HandleBGPFilterDeleted(filter)
}

// HandleBGPDefinedSetAdded handles BGP defined set addition directly
func (w *BGPWatcher) HandleBGPDefinedSetAdded(definedSet *bgpapi.DefinedSet) error {
	w.log.Debugf("BGP watcher delegating defined set added to handler")
	return w.bgpHandler.HandleBGPDefinedSetAdded(definedSet)
}

// HandleBGPDefinedSetDeleted handles BGP defined set deletion directly
func (w *BGPWatcher) HandleBGPDefinedSetDeleted(definedSet *bgpapi.DefinedSet) error {
	w.log.Debugf("BGP watcher delegating defined set deleted to handler")
	return w.bgpHandler.HandleBGPDefinedSetDeleted(definedSet)
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

func (w *BGPWatcher) injectRoute(path *bgpapi.Path) error {
	w.log.Debugf("BGP watcher delegating route injection to handler")
	return w.bgpHandler.InjectRoute(path)
}

func (w *BGPWatcher) injectSRv6Policy(path *bgpapi.Path) error {
	w.log.Debugf("BGP watcher delegating SRv6 policy injection to handler")
	return w.bgpHandler.InjectSRv6Policy(path)
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
					// SRv6 feature gate check removed; always process SRv6 if path family matches
					if path.GetFamily() == &common.BgpFamilySRv6IPv6 {
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

// WatchBGPPath watches BGP routes from other peers and inject them into linux kernel
// TODO: multipath support
func (w *BGPWatcher) WatchBGPPath(t *tomb.Tomb) error {
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
		err = w.bgpHandler.InitialPolicySetting(false /* isv6 */)
		if err != nil {
			return errors.Wrap(err, "error configuring initial policies")
		}
	}
	if nodeIP6 != nil {
		err = w.bgpHandler.InitialPolicySetting(true /* isv6 */)
		if err != nil {
			return errors.Wrap(err, "error configuring initial policies")
		}
	}

	w.log.Infof("BGP Watcher is running ")

	stopBGPMonitoring, err := w.startBGPMonitoring()
	if err != nil {
		return errors.Wrap(err, "error starting BGP monitoring")
	}

	<-t.Dying()
	stopBGPMonitoring()
	err = w.BGPServer.StopBgp(context.Background(), &bgpapi.StopBgpRequest{})
	if err != nil {
		w.log.Errorf("failed to stop BGP server: %s", err)
	}
	w.log.Infof("BGP Watcher asked to stop")
	return nil
}
