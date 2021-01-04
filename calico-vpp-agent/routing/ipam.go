// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"sync"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocliv3 "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// contains returns true if the IPPool contains 'prefix'
func contains(pool *calicov3.IPPool, prefix *net.IPNet) (bool, error) {
	_, poolCIDR, _ := net.ParseCIDR(pool.Spec.CIDR) // this field is validated so this should never error
	poolCIDRLen, poolCIDRBits := poolCIDR.Mask.Size()
	prefixLen, prefixBits := prefix.Mask.Size()
	return poolCIDRBits == prefixBits && poolCIDR.Contains(prefix.IP) && prefixLen >= poolCIDRLen, nil
}

// Compare only the fields that make a difference for this agent i.e. the fields that have an impact on routing
func equalPools(a *calicov3.IPPool, b *calicov3.IPPool) bool {
	if a.Spec.CIDR != b.Spec.CIDR {
		return false
	}
	if a.Spec.IPIPMode != b.Spec.IPIPMode {
		return false
	}
	if a.Spec.VXLANMode != b.Spec.VXLANMode {
		return false
	}
	return true
}

type IpamCache interface {
	GetPrefixIPPool(*net.IPNet) *calicov3.IPPool
	SyncIPAM() error
	WaitReady()
	OnVppRestart() error
	IPNetNeedsSNAT(prefix *net.IPNet) bool
}

type ipamCache struct {
	lock          sync.RWMutex
	ippoolmap     map[string]*calicov3.IPPool
	client        calicocliv3.Interface
	updateHandler func(*calicov3.IPPool, *calicov3.IPPool) error
	ready         bool
	readyCond     *sync.Cond
	log           *logrus.Entry
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *ipamCache) GetPrefixIPPool(prefix *net.IPNet) *calicov3.IPPool {
	if !c.ready {
		c.readyCond.L.Lock()
		for !c.ready {
			c.readyCond.Wait()
		}
		c.readyCond.L.Unlock()
	}
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, pool := range c.ippoolmap {
		in, err := contains(pool, prefix)
		if err != nil {
			c.log.Warnf("contains errored: %v", err)
			continue
		}
		if in {
			return pool
		}
	}
	return nil
}

func (c *ipamCache) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	pool := c.GetPrefixIPPool(prefix)
	if pool == nil {
		return false
	} else {
		return pool.Spec.NATOutgoing
	}

}

// update updates the internal map with IPAM updates when the update
// is new addtion to the map or changes the existing item, it calls
// updateHandler
func (c *ipamCache) handleIPPoolUpdate(pool calicov3.IPPool, del bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.log.Debugf("update ipam cache: %+v, %t", pool.Spec, del)
	key := pool.Spec.CIDR

	existing := c.ippoolmap[key]
	if del {
		delete(c.ippoolmap, key)
		return c.updateHandler(nil, existing)
	} else if existing != nil && equalPools(&pool, existing) {
		return nil
	}

	c.ippoolmap[key] = &pool

	return c.updateHandler(&pool, existing)
}

// sync synchronizes the IP pools stored under /calico/v1/ipam
func (c *ipamCache) SyncIPAM() error {
	for {
		c.log.Info("Reconciliating pools...")
		poolsList, err := c.client.IPPools().List(context.Background(), options.ListOptions{})
		if err != nil {
			return errors.Wrap(err, "error listing pools")
		}
		sweepMap := make(map[string]bool)
		for _, pool := range poolsList.Items {
			sweepMap[pool.Spec.CIDR] = true
			err := c.handleIPPoolUpdate(pool, false)
			if err != nil {
				return errors.Wrap(err, "error processing startup pool update")
			}
		}
		// Sweep phase
		for key, pool := range c.ippoolmap {
			found := sweepMap[key]
			if !found {
				c.handleIPPoolUpdate(*pool, true)
			}
		}

		if !c.ready {
			c.readyCond.L.Lock()
			c.ready = true
			c.readyCond.Broadcast()
			c.readyCond.L.Unlock()
		}

		poolsWatcher, err := c.client.IPPools().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: poolsList.ResourceVersion},
		)
		if err != nil {
			return errors.Wrap(err, "error watching pools")
		}
	watch:
		for update := range poolsWatcher.ResultChan() {
			del := false
			pool := update.Object
			switch update.Type {
			case watch.Error:
				c.log.Infof("ipam watch returned an error")
				break watch
			case watch.Deleted:
				del = true
				pool = update.Previous
			case watch.Added, watch.Modified:
			}
			if err = c.handleIPPoolUpdate(*pool.(*calicov3.IPPool), del); err != nil {
				return errors.Wrap(err, "error processing pool update")
			}
		}
	}
	return nil
}

func (c *ipamCache) OnVppRestart() error {
	for _, pool := range c.ippoolmap {
		err := c.updateHandler(pool, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ipamCache) WaitReady() {
	c.readyCond.L.Lock()
	for !c.ready {
		c.readyCond.Wait()
	}
	c.readyCond.L.Unlock()
}

// create new IPAM cache
func newIPAMCache(log *logrus.Entry, client calicocliv3.Interface, updateHandler func(*calicov3.IPPool, *calicov3.IPPool) error) *ipamCache {
	cond := sync.NewCond(&sync.Mutex{})
	return &ipamCache{
		ippoolmap:     make(map[string]*calicov3.IPPool),
		updateHandler: updateHandler,
		client:        client,
		readyCond:     cond,
		log:           log,
		ready:         false,
	}
}
