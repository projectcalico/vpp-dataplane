// Copyright (C) 2019 Cisco Systems Inc.
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

package main

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type PoolWatcher struct {
	stop         chan struct{}
	RouteWatcher *RouteWatcher
	params       *config.VppManagerParams
	conf         *config.InterfaceConfig
}

func (p *PoolWatcher) Stop() {
	log.Info("Stopping pools watcher...")
	p.stop <- struct{}{}
}

func (p *PoolWatcher) getNetworkRoute(network string) (route *netlink.Route, err error) {
	log.Infof("Added ip pool %s", network)
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", network)
	}

	gw := fakeNextHopIP4
	if cidr.IP.To4() == nil {
		gw = fakeNextHopIP6
	}

	return &netlink.Route{
		Dst:      cidr,
		Gw:       gw,
		Protocol: syscall.RTPROT_STATIC,
		MTU:      config.GetUplinkMtu(p.params, p.conf, true /* includeEncap */),
	}, nil
}

func (p *PoolWatcher) poolAdded(network string) error {
	route, err := p.getNetworkRoute(network)
	if err != nil {
		return errors.Wrap(err, "Error adding net")
	}
	err = p.RouteWatcher.AddRoute(route)
	return errors.Wrapf(err, "cannot add pool route %s through vpp tap", network)
}

func (p *PoolWatcher) poolDeleted(network string) error {
	route, err := p.getNetworkRoute(network)
	if err != nil {
		return errors.Wrap(err, "Error deleting net")
	}
	err = p.RouteWatcher.DelRoute(route)
	return errors.Wrapf(err, "cannot delete pool route %s through vpp tap", network)
}

func (p *PoolWatcher) SyncPools() {
	p.stop = make(chan struct{}, 1)
	pools := make(map[string]interface{})
	log.Info("Starting pools watcher...")
	for {
		var poolsWatcher watch.Interface = nil
		var eventChannel <-chan watch.Event = nil
		var poolsList *calicoapi.IPPoolList
		sweepMap := make(map[string]interface{})

		/* Need to recreate the client at each loop if pipe breaks */
		client, err := calicocli.NewFromEnv()
		if err != nil {
			log.Errorf("error creating calico client: %v", err)
			goto restart
		}
		poolsList, err = client.IPPools().List(context.Background(), options.ListOptions{})
		if err != nil {
			log.Errorf("error listing pools: %v", err)
			goto restart
		}
		for _, pool := range poolsList.Items {
			key := pool.Spec.CIDR
			sweepMap[key] = nil
			_, exists := pools[key]
			if !exists {
				pools[key] = nil
				err = p.poolAdded(key)
				if err != nil {
					log.Errorf("error adding pool %s: %v", err)
					goto restart
				}
			}
		}
		// Sweep phase
		for key, _ := range pools {
			_, found := sweepMap[key]
			if !found {
				err = p.poolDeleted(key)
				if err != nil {
					log.Errorf("error deleting pool %s: %v", err)
					goto restart
				}
				delete(pools, key)
			}
		}

		poolsWatcher, err = client.IPPools().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: poolsList.ResourceVersion},
		)
		if err != nil {
			log.Errorf("error watching pools: %v", err)
			goto restart
		}

		eventChannel = poolsWatcher.ResultChan()
		for {
			select {
			case update, ok := <-eventChannel:
				if !ok {
					eventChannel = nil
					goto restart
				}
				switch update.Type {
				case watch.Error:
					log.Infof("Watch returned an error")
					goto restart
				case watch.Added, watch.Modified:
					pool := update.Object.(*calicoapi.IPPool)
					key := pool.Spec.CIDR
					err = p.poolAdded(key)
					if err != nil {
						log.Errorf("error adding pool %s: %v", err)
						goto restart
					}
					pools[key] = nil
				case watch.Deleted:
					pool := update.Previous.(*calicoapi.IPPool)
					key := pool.Spec.CIDR
					err = p.poolDeleted(key)
					if err != nil {
						log.Errorf("error deleting pool %s: %v", err)
						goto restart
					}
					delete(pools, key)
				}
			case <-p.stop:
				log.Info("Pools watcher stopped")
				poolsWatcher.Stop()
				return
			}
		}
	restart:
		log.Info("restarting pools watcher...")
		if poolsWatcher != nil {
			poolsWatcher.Stop()
		}
		time.Sleep(2 * time.Second)
	}
}
