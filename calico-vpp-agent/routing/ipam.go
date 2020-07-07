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
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// contains returns true if the IPPool contains 'prefix'
func contains(pool *calicov3.IPPool, prefix net.IPNet) (bool, error) {
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

type ipamCache struct {
	mu            sync.RWMutex
	m             map[string]*calicov3.IPPool
	client        calicocliv3.Interface
	updateHandler func(*calicov3.IPPool, *calicov3.IPPool) error
	ready         bool
	readyCond     *sync.Cond
	l             *logrus.Entry
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *ipamCache) match(prefix net.IPNet) *calicov3.IPPool {
	if !c.ready {
		c.readyCond.L.Lock()
		for !c.ready {
			c.readyCond.Wait()
		}
		c.readyCond.L.Unlock()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.m {
		in, err := contains(p, prefix)
		if err != nil {
			c.l.Warnf("contains errored: %v", err)
			continue
		}
		if in {
			return p
		}
	}
	return nil
}

// update updates the internal map with IPAM updates when the update
// is new addtion to the map or changes the existing item, it calls
// updateHandler
func (c *ipamCache) update(pool calicov3.IPPool, del bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.l.Debugf("update ipam cache: %+v, %t", pool.Spec, del)
	key := pool.Spec.CIDR

	existing := c.m[key]
	if del {
		delete(c.m, key) // Should we cal updateHandler here (and modify it to handle deletions)?
		return nil
	} else if existing != nil && equalPools(&pool, existing) {
		return nil
	}

	c.m[key] = &pool

	if c.updateHandler != nil {
		return c.updateHandler(&pool, existing)
	}
	return nil
}

// sync synchronizes the IP pools stored under /calico/v1/ipam
func (c *ipamCache) sync() error {
	for {
		c.l.Info("Reconciliating pools...")
		poolsList, err := c.client.IPPools().List(context.Background(), options.ListOptions{})
		if err != nil {
			return errors.Wrap(err, "error listing pools")
		}
		sweepMap := make(map[string]bool)
		for _, pool := range poolsList.Items {
			sweepMap[pool.Spec.CIDR] = true
			err := c.update(pool, false)
			if err != nil {
				return errors.Wrap(err, "error processing startup pool update")
			}
		}
		// Sweep phase
		for key, pool := range c.m {
			found := sweepMap[key]
			if !found {
				c.update(*pool, true)
			}
		}

		if !c.ready {
			c.ready = true
			c.readyCond.Broadcast()
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
				switch update.Error.(type) {
				case calicoerr.ErrorWatchTerminated:
					break watch
				default:
					return errors.Wrap(update.Error, "error while watching IPPools")
				}
			case watch.Deleted:
				del = true
				pool = update.Previous
			case watch.Added, watch.Modified:
			}
			if err = c.update(*pool.(*calicov3.IPPool), del); err != nil {
				return errors.Wrap(err, "error processing pool update")
			}
		}
	}
	return nil
}

// create new IPAM cache
func newIPAMCache(l *logrus.Entry, client calicocliv3.Interface, updateHandler func(*calicov3.IPPool, *calicov3.IPPool) error) *ipamCache {
	cond := sync.NewCond(&sync.Mutex{})
	return &ipamCache{
		m:             make(map[string]*calicov3.IPPool),
		updateHandler: updateHandler,
		client:        client,
		readyCond:     cond,
		l:             l,
	}
}
