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

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

// BGPRouteHandler defines the interface for handling BGP routes and policies
type BGPRouteHandler interface {
	InitialPolicySetting(isv6 bool) error
	InjectRoute(path *bgpapi.Path) error
	InjectSRv6Policy(path *bgpapi.Path) error
}

type BGPWatcher struct {
	log   *logrus.Entry
	cache *cache.Cache

	BGPServer   *bgpserver.BgpServer
	nodeBGPSpec *common.LocalNodeSpec
	bgpHandler  BGPRouteHandler
}

func NewBGPWatcher(cache *cache.Cache, log *logrus.Entry) *BGPWatcher {
	watcher := &BGPWatcher{
		log:   log,
		cache: cache,
	}

	return watcher
}

func (w *BGPWatcher) SetBGPServer(bgpServer *bgpserver.BgpServer) {
	w.BGPServer = bgpServer
}

func (w *BGPWatcher) SetBGPHandler(handler BGPRouteHandler) {
	w.bgpHandler = handler
}

func (w *BGPWatcher) injectRoute(path *bgpapi.Path) error {
	if w.bgpHandler == nil {
		w.log.Warnf("BGP handler not set, cannot inject route")
		return nil
	}
	return w.bgpHandler.InjectRoute(path)
}

func (w *BGPWatcher) injectSRv6Policy(path *bgpapi.Path) error {
	if w.bgpHandler == nil {
		w.log.Warnf("BGP handler not set, cannot inject SRv6 policy")
		return nil
	}
	return w.bgpHandler.InjectSRv6Policy(path)
}

func (w *BGPWatcher) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	w.nodeBGPSpec = nodeBGPSpec
}

func (w *BGPWatcher) getListenPort() uint16 {
	return w.cache.BGPConf.ListenPort
}

func (w *BGPWatcher) getGoBGPGlobalConfig() (*bgpapi.Global, error) {
	var routerID string
	listenAddresses := make([]string, 0)
	asn := w.nodeBGPSpec.ASNumber
	if asn == nil {
		asn = w.cache.BGPConf.ASNumber
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
					// Only process SRv6 if feature gate is enabled and path family matches
					if config.GetCalicoVppFeatureGates().SRv6Enabled != nil && *config.GetCalicoVppFeatureGates().SRv6Enabled && path.GetFamily() == &common.BgpFamilySRv6IPv6 {
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

	// Set up initial BGP policies for route export
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	if nodeIP4 != nil && w.bgpHandler != nil {
		err = w.bgpHandler.InitialPolicySetting(false /* isv6 */)
		if err != nil {
			return errors.Wrap(err, "error configuring initial policies for IPv4")
		}
	}
	if nodeIP6 != nil && w.bgpHandler != nil {
		err = w.bgpHandler.InitialPolicySetting(true /* isv6 */)
		if err != nil {
			return errors.Wrap(err, "error configuring initial policies for IPv6")
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
