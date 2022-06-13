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
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

// contains returns true if the IPPool contains 'prefix'
func contains(pool *proto.IPAMPoolUpdate, prefix *net.IPNet) (bool, error) {
	_, poolCIDR, _ := net.ParseCIDR(pool.Pool.Cidr) // this field is validated so this should never error
	poolCIDRLen, poolCIDRBits := poolCIDR.Mask.Size()
	prefixLen, prefixBits := prefix.Mask.Size()
	return poolCIDRBits == prefixBits && poolCIDR.Contains(prefix.IP) && prefixLen >= poolCIDRLen, nil
}

// Compare only the fields that make a difference for this agent i.e. the fields that have an impact on routing
func equalPools(a *proto.IPAMPoolUpdate, b *proto.IPAMPoolUpdate) bool {
	if a.Pool.Cidr != b.Pool.Cidr {
		return false
	}
	if a.Pool.IpipMode != b.Pool.IpipMode {
		return false
	}
	if a.Pool.VxlanMode != b.Pool.VxlanMode {
		return false
	}
	return true
}

type IpamCache interface {
	GetPrefixIPPool(*net.IPNet) *proto.IPAMPoolUpdate
	SyncIPAM(t *tomb.Tomb) error
	WaitReady()
	IPNetNeedsSNAT(prefix *net.IPNet) bool
}

type ipamCache struct {
	log       *logrus.Entry
	lock      sync.RWMutex
	ippoolmap map[string]proto.IPAMPoolUpdate
	ready     bool
	readyCond *sync.Cond
	clientv3  calicov3cli.Interface
	vpp       *vpplink.VppLink

	currentWatchRevision string

	ipamEventChan chan common.CalicoVppEvent
}

func (c *ipamCache) ForceReady() {
	c.ready = true
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *ipamCache) GetPrefixIPPool(prefix *net.IPNet) *proto.IPAMPoolUpdate {
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
		c.log.Debugf("Available %s=%v", k, pool)
	}
	return nil
}

func (c *ipamCache) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	pool := c.GetPrefixIPPool(prefix)
	if pool == nil {
		return false
	} else {
		return pool.Pool.Masquerade
	}

}

// update updates the internal map with IPAM updates when the update
// is new addtion to the map or changes the existing item, it calls
// ipamUpdateHandler
func (c *ipamCache) handleIPPoolUpdate(poolUpdate *proto.IPAMPoolUpdate, poolRemove *proto.IPAMPoolRemove) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	key := ""
	if poolUpdate != nil {
		key = poolUpdate.Id
	} else {
		key = poolRemove.Id
	}

	if key == "" {
		c.log.Debugf("Empty pool")
		return nil
	}

	existing, found := c.ippoolmap[key]
	if poolRemove != nil {
		if found {
			delete(c.ippoolmap, key)
			c.log.Infof("Deleting pool: %s", key)
			return c.ipamUpdateHandler(nil, &existing)
		} else {
			c.log.Warnf("Deleting unknown ippool")
			return nil
		}
	} else {
		if found && equalPools(poolUpdate, &existing) {
			c.log.Infof("Unchanged pool: %s, nat:%t", key, poolUpdate.Pool.Masquerade)
			return nil
		} else if found {
			c.log.Infof("Updating pool: %s, nat:%t", key, poolUpdate.Pool.Masquerade)
			c.ippoolmap[key] = *poolUpdate

			return c.ipamUpdateHandler(poolUpdate, &existing)
		} else {
			c.log.Infof("Adding pool: %s, nat:%t", key, poolUpdate.Pool.Masquerade)
			c.ippoolmap[key] = *poolUpdate
			return c.ipamUpdateHandler(poolUpdate, nil /* prevPool */)
		}
	}
}

// sync synchronizes the IP pools stored under /calico/v1/ipam
func (c *ipamCache) SyncIPAM(t *tomb.Tomb) error {
	for t.Alive() {
		c.currentWatchRevision = ""
		err := c.resync()
		if err != nil {
			c.log.Error(err, "error watching pools")
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				c.log.Infof("IPAM Watcher asked to stop")
				return nil
			case event := <-c.ipamEventChan:
				switch event.Type {
				case common.IpamPoolUpdate:
					pool := event.New.(*proto.IPAMPoolUpdate)
					if pool != nil {
						err = c.handleIPPoolUpdate(pool, nil)
						if err != nil {
							return errors.Wrap(err, "error processing pool add / modified")
						}
					}
				case common.IpamPoolRemove:
					pool := event.Old.(*proto.IPAMPoolRemove)
					if pool != nil {
						err = c.handleIPPoolUpdate(nil, pool)
						if err != nil {
							return errors.Wrap(err, "error processing pool del")
						}
					}
				}
			}
		}
	restart:
		c.log.Debug("restarting IPAM watcher...")
		time.Sleep(2 * time.Second)
	}
	c.log.Infof("Ipam Watcher returned")

	return nil
}

func (c *ipamCache) resync() error {
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
			poolUpdate := &proto.IPAMPoolUpdate{
				Id: strings.Replace(pool.Spec.CIDR, "/", "-", 1), // same as felix
				Pool: &proto.IPAMPool{
					Cidr:       pool.Spec.CIDR,
					Masquerade: pool.Spec.NATOutgoing,
					IpipMode:   string(pool.Spec.IPIPMode),
					VxlanMode:  string(pool.Spec.VXLANMode),
				}}
			err := c.handleIPPoolUpdate(poolUpdate, nil)
			if err != nil {
				return errors.Wrap(err, "error processing startup pool update")
			}
		}
		// Sweep phase
		for key, pool := range c.ippoolmap {
			found := sweepMap[key]
			if !found {
				err := c.handleIPPoolUpdate(nil, &proto.IPAMPoolRemove{Id: pool.Id})
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
	return nil
}

func (c *ipamCache) addDelSnatPrefix(pool *proto.IPAMPoolUpdate, isAdd bool) (err error) {
	_, ipNet, err := net.ParseCIDR(pool.Pool.Cidr)
	if err != nil {
		return errors.Wrapf(err, "Couldn't parse pool CIDR %s", pool.Pool.Cidr)
	}
	if pool.Pool.Masquerade {
		err = c.vpp.CnatAddDelSnatPrefix(ipNet, isAdd)
		if err != nil {
			return errors.Wrapf(err, "Couldn't configure SNAT prefix")
		}
	}
	return nil
}

func (c *ipamCache) ipamUpdateHandler(poolUpdate *proto.IPAMPoolUpdate, prevPoolUpdate *proto.IPAMPoolUpdate) (err error) {
	if prevPoolUpdate == nil {
		/* Add */
		c.log.Debugf("Pool %v Added, handler called", poolUpdate)
		err = c.addDelSnatPrefix(poolUpdate, true /* isAdd */)
		if err != nil {
			return errors.Wrap(err, "error handling ipam add")
		}
	} else if poolUpdate == nil {
		/* Deletion */
		c.log.Debugf("Pool %s deleted, handler called", prevPoolUpdate.Pool.Cidr)
		err = c.addDelSnatPrefix(prevPoolUpdate, false /* isAdd */)
		if err != nil {
			return errors.Wrap(err, "error handling ipam deletion")
		}
	} else {
		if poolUpdate.Pool.Cidr != prevPoolUpdate.Pool.Cidr ||
			poolUpdate.Pool.Masquerade != prevPoolUpdate.Pool.Masquerade {
			var err, err2 error
			err = c.addDelSnatPrefix(prevPoolUpdate, false /* isAdd */)
			err2 = c.addDelSnatPrefix(poolUpdate, true /* isAdd */)
			if err != nil || err2 != nil {
				return errors.Errorf("error updating snat prefix del:%s, add:%s", err, err2)
			}
		}
	}

	var prevPoolUpdateCopy *proto.IPAMPool
	var poolUpdateCopy *proto.IPAMPool
	if prevPoolUpdate != nil {
		prevPoolUpdateCopy = &proto.IPAMPool{IpipMode: prevPoolUpdate.Pool.IpipMode, VxlanMode: prevPoolUpdate.Pool.VxlanMode, Cidr: prevPoolUpdate.Pool.Cidr}
	}
	if poolUpdate != nil {
		poolUpdateCopy = &proto.IPAMPool{IpipMode: poolUpdate.Pool.IpipMode, VxlanMode: poolUpdate.Pool.VxlanMode, Cidr: poolUpdate.Pool.Cidr}
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.IpamConfChanged,
		Old:  prevPoolUpdateCopy,
		New:  poolUpdateCopy,
	})
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
	ipamCache := &ipamCache{
		vpp:           vpp,
		log:           log,
		clientv3:      clientv3,
		ippoolmap:     make(map[string]proto.IPAMPoolUpdate),
		readyCond:     cond,
		ready:         false,
		ipamEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
	}
	reg := common.RegisterHandler(ipamCache.ipamEventChan, "ipam pool watcher events")
	reg.ExpectEvents(common.IpamPoolRemove, common.IpamPoolUpdate)
	return ipamCache
}
