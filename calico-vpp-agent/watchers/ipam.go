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

package watchers

import (
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
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
	SyncIPAM(t *tomb.Tomb) error
	WaitReady()
	IPNetNeedsSNAT(prefix *net.IPNet) bool
}

type ipamCache struct {
	log       *logrus.Entry
	lock      sync.RWMutex
	ippoolmap map[string]calicov3.IPPool
	ready     bool
	readyCond *sync.Cond
	clientv3  calicov3cli.Interface
	vpp       *vpplink.VppLink

	watcher              watch.Interface
	currentWatchRevision string
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
		in, err := contains(&pool, prefix)
		if err != nil {
			c.log.Warnf("contains errored: %v", err)
			continue
		}
		if in {
			return &pool
		}
	}
	c.log.Warnf("No pool found: for %s", prefix)
	for k, pool := range c.ippoolmap {
		c.log.Debugf("Available %s=%s", k, pool)
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
// ipamUpdateHandler
func (c *ipamCache) handleIPPoolUpdate(pool *calicov3.IPPool, isDel bool) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	key := pool.Spec.CIDR

	if key == "" {
		c.log.Debugf("Empty pool")
		return nil
	}

	existing, found := c.ippoolmap[key]
	if isDel {
		if found {
			delete(c.ippoolmap, key)
			c.log.Infof("Deleting pool: %s, nat:%t", key, pool.Spec.NATOutgoing)
			return c.ipamUpdateHandler(nil, &existing)
		} else {
			c.log.Warnf("Deleting unknown ippool")
			return nil
		}
	} else {
		if found && equalPools(pool, &existing) {
			c.log.Infof("Unchanged pool: %s, nat:%t", key, pool.Spec.NATOutgoing)
			return nil
		} else if found {
			c.log.Infof("Updating pool: %s, nat:%t", key, pool.Spec.NATOutgoing)
			c.ippoolmap[key] = *pool

			return c.ipamUpdateHandler(pool, &existing)
		} else {
			c.log.Infof("Adding pool: %s, nat:%t", key, pool.Spec.NATOutgoing)
			c.ippoolmap[key] = *pool
			return c.ipamUpdateHandler(pool, nil /* prevPool */)
		}
	}
}

// sync synchronizes the IP pools stored under /calico/v1/ipam
func (c *ipamCache) SyncIPAM(t *tomb.Tomb) error {
	for t.Alive() {
		c.currentWatchRevision = ""
		err := c.resyncAndCreateWatcher()
		if err != nil {
			c.log.Error(err, "error watching pools")
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				c.log.Infof("IPAM Watcher asked to stop")
				c.cleanExistingWatcher()
				return nil
			case update, ok := <-c.watcher.ResultChan():
				if !ok {
					c.log.Debug("ipam watch channel closed - restarting")
					err := c.resyncAndCreateWatcher()
					if err != nil {
						goto restart
					}
					continue
				}
				switch update.Type {
				case watch.EventType(api.WatchError):
					c.log.Debug("ipam watch returned, restarting...")
					goto restart
				case watch.Deleted:
					pool, _ := update.Previous.(*calicov3.IPPool)
					err = c.handleIPPoolUpdate(pool, true /* del */)
					if err != nil {
						return errors.Wrap(err, "error processing pool del")
					}
				case watch.Added, watch.Modified:
					pool, _ := update.Object.(*calicov3.IPPool)
					if pool != nil {
						err = c.handleIPPoolUpdate(pool, false /* del */)
						if err != nil {
							return errors.Wrap(err, "error processing pool add / modified")
						}
					}
				}
			}
		}
	restart:
		c.log.Debug("restarting IPAM watcher...")
		c.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	c.log.Infof("Ipam Watcher returned")

	return nil
}

func (c *ipamCache) resyncAndCreateWatcher() error {
	if c.currentWatchRevision == "" {
		c.log.Info("Reconciliating pools...")
		poolsList, err := c.clientv3.IPPools().List(context.Background(), options.ListOptions{
			ResourceVersion: c.currentWatchRevision,
		})
		if err != nil {
			return errors.Wrap(err, "cannot list pools")
		}
		c.currentWatchRevision = poolsList.ResourceVersion
		sweepMap := make(map[string]bool)
		for _, pool := range poolsList.Items {
			sweepMap[pool.Spec.CIDR] = true
			err := c.handleIPPoolUpdate(&pool, false /*isdel*/)
			if err != nil {
				return errors.Wrap(err, "error processing startup pool update")
			}
		}
		// Sweep phase
		for key, pool := range c.ippoolmap {
			found := sweepMap[key]
			if !found {
				err := c.handleIPPoolUpdate(&pool, true /*isdel*/)
				if err != nil {
					c.log.Errorf("error deleting ippool %s", err)
				}
			}
		}

		if !c.ready {
			c.readyCond.L.Lock()
			c.ready = true
			c.readyCond.Broadcast()
			c.readyCond.L.Unlock()
		}
	}
	c.cleanExistingWatcher()
	poolsWatcher, err := c.clientv3.IPPools().Watch(
		context.Background(),
		options.ListOptions{ResourceVersion: c.currentWatchRevision},
	)
	if err != nil {
		return errors.Wrap(err, "cannot watch pools %v")
	}
	c.watcher = poolsWatcher
	return nil
}

func (c *ipamCache) cleanExistingWatcher() {
	if c.watcher != nil {
		c.watcher.Stop()
		c.log.Debug("Stopped watcher")
		c.watcher = nil
	}
}

func (c *ipamCache) addDelSnatPrefix(pool *calicov3.IPPool, isAdd bool) (err error) {
	_, ipNet, err := net.ParseCIDR(pool.Spec.CIDR)
	if err != nil {
		return errors.Wrapf(err, "Couldn't parse pool CIDR %s", pool.Spec.CIDR)
	}
	if pool.Spec.NATOutgoing {
		err = c.vpp.CnatAddDelSnatPrefix(ipNet, isAdd)
		if err != nil {
			return errors.Wrapf(err, "Couldn't configure SNAT prefix")
		}
	}
	return nil
}

func (c *ipamCache) ipamUpdateHandler(pool *calicov3.IPPool, prevPool *calicov3.IPPool) (err error) {
	if prevPool == nil {
		/* Add */
		c.log.Debugf("Pool %s Added, handler called")
		err = c.addDelSnatPrefix(pool, true /* isAdd */)
		return errors.Wrap(err, "error handling ipam add")
	} else if pool == nil {
		/* Deletion */
		c.log.Debugf("Pool %s deleted, handler called", prevPool.Spec.CIDR)
		err = c.addDelSnatPrefix(prevPool, false /* isAdd */)
		return errors.Wrap(err, "error handling ipam deletion")
	} else {
		if pool.Spec.CIDR != prevPool.Spec.CIDR ||
			pool.Spec.NATOutgoing != prevPool.Spec.NATOutgoing {
			var err, err2 error
			err = c.addDelSnatPrefix(prevPool, false /* isAdd */)
			err2 = c.addDelSnatPrefix(pool, true /* isAdd */)
			if err != nil || err2 != nil {
				return errors.Errorf("error updating snat prefix del:%s, add:%s", err, err2)
			}
		}
		common.SendEvent(common.CalicoVppEvent{
			Type: common.IpamConfChanged,
			Old:  prevPool,
			New:  pool,
		})
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
func NewIPAMCache(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, log *logrus.Entry) *ipamCache {
	cond := sync.NewCond(&sync.Mutex{})
	return &ipamCache{
		vpp:       vpp,
		log:       log,
		clientv3:  clientv3,
		ippoolmap: make(map[string]calicov3.IPPool),
		readyCond: cond,
		ready:     false,
	}
}
