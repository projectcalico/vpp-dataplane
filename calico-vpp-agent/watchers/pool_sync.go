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

package watchers

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	tomb "gopkg.in/tomb.v2"
)

type PoolWatcher struct {
	RouteWatcher *RouteWatcher

	watcher              watch.Interface
	currentWatchRevision string
	UserSpecifiedMtu     int
	Mtu                  int
	FakeNextHopIP4       net.IP
	FakeNextHopIP6       net.IP
}

func (p *PoolWatcher) getNetworkRoute(network string) (route *netlink.Route, err error) {
	log.Infof("Added ip pool %s", network)
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", network)
	}

	gw := p.FakeNextHopIP4
	if cidr.IP.To4() == nil {
		gw = p.FakeNextHopIP6
	}

	return &netlink.Route{
		Dst:      cidr,
		Gw:       gw,
		Protocol: syscall.RTPROT_STATIC,
		MTU:      GetUplinkMtu(p.UserSpecifiedMtu, p.Mtu, true /* includeEncap */),
	}, nil
}

func GetUplinkMtu(userSpecifiedMtu int, mtu int, includeEncap bool) int {
	encapSize := 0
	if includeEncap {
		encapSize = config.DefaultEncapSize
	}
	// Use the linux interface MTU as default value if nothing is configured from env
	if userSpecifiedMtu == 0 {
		return mtu - encapSize
	}
	return userSpecifiedMtu - encapSize
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

func (p *PoolWatcher) SyncPools(t *tomb.Tomb) error {
	pools := make(map[string]interface{})
	log.Info("Starting pools watcher...")
	for t.Alive() {
		p.currentWatchRevision = ""
		err := p.resyncAndCreateWatcher(pools)
		if err != nil {
			log.Error(err)
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				log.Info("Pools watcher stopped")
				p.cleanExistingWatcher()
				return nil
			case update, ok := <-p.watcher.ResultChan():
				if !ok {
					err := p.resyncAndCreateWatcher(pools)
					if err != nil {
						log.Error(err)
						goto restart
					}
					continue
				}
				switch update.Type {
				case watch.Error:
					log.Debug("pool sync watch returned, restarting...")
					goto restart
				case watch.Added, watch.Modified:
					pool := update.Object.(*calicov3.IPPool)
					key := pool.Spec.CIDR
					err = p.poolAdded(key)
					if err != nil {
						log.Errorf("error adding pool %s: %v", err)
						goto restart
					}
					pools[key] = nil
				case watch.Deleted:
					pool := update.Previous.(*calicov3.IPPool)
					key := pool.Spec.CIDR
					err = p.poolDeleted(key)
					if err != nil {
						log.Errorf("error deleting pool %s: %v", err)
						goto restart
					}
					delete(pools, key)
				}
			}
		}
	restart:
		log.Debug("restarting pools watcher...")
		p.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	return nil
}

func (p *PoolWatcher) resyncAndCreateWatcher(pools map[string]interface{}) error {
restart:
	/* Need to recreate the client at each loop if pipe breaks */
	client, err := calicov3cli.NewFromEnv()
	if err != nil {
		return errors.Wrap(err, "error creating calico client: %v")
	}
	if p.currentWatchRevision == "" {
		var poolsList *calicov3.IPPoolList
		sweepMap := make(map[string]interface{})

		poolsList, err = client.IPPools().List(context.Background(), options.ListOptions{
			ResourceVersion: p.currentWatchRevision,
		})
		if err != nil {
			log.Errorf("error listing pools: %v", err)
			time.Sleep(3 * time.Second)
			goto restart
		}
		p.currentWatchRevision = poolsList.ResourceVersion
		for _, pool := range poolsList.Items {
			key := pool.Spec.CIDR
			sweepMap[key] = nil
			_, exists := pools[key]
			if !exists {
				pools[key] = nil
				err = p.poolAdded(key)
				if err != nil {
					return errors.Wrap(err, "error adding pool %s: %v")
				}
			}
		}
		// Sweep phase
		for key := range pools {
			_, found := sweepMap[key]
			if !found {
				err = p.poolDeleted(key)
				if err != nil {
					return errors.Wrap(err, "error deleting pool %s: %v")
				}
				delete(pools, key)
			}
		}
	}
	p.cleanExistingWatcher()
	poolsWatcher, err := client.IPPools().Watch(
		context.Background(),
		options.ListOptions{ResourceVersion: p.currentWatchRevision},
	)
	if err != nil {
		log.Errorf("cannot watch pools %v", err)
		time.Sleep(3 * time.Second)
		goto restart
	}
	p.watcher = poolsWatcher
	return nil
}

func (p *PoolWatcher) cleanExistingWatcher() {
	if p.watcher != nil {
		p.watcher.Stop()
		log.Debug("Stopped watcher")
		p.watcher = nil
	}
}
