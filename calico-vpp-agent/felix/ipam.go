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
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

func (s *Server) handleIpamPoolUpdate(msg *proto.IPAMPoolUpdate) (err error) {
	if msg.GetId() == "" {
		s.log.Debugf("Empty pool")
		return nil
	}
	s.ippoolLock.Lock()
	defer s.ippoolLock.Unlock()

	newIpamPool := msg.GetPool()
	oldIpamPool, found := s.cache.IPPoolMap[msg.GetId()]
	if found && ipamPoolEquals(newIpamPool, oldIpamPool) {
		s.log.Infof("Unchanged pool: %s, nat:%t", msg.GetId(), newIpamPool.GetMasquerade())
		return nil
	} else if found {
		s.log.Infof("Updating pool: %s, nat:%t", msg.GetId(), newIpamPool.GetMasquerade())
		s.cache.IPPoolMap[msg.GetId()] = newIpamPool
		if newIpamPool.GetCidr() != oldIpamPool.GetCidr() ||
			newIpamPool.GetMasquerade() != oldIpamPool.GetMasquerade() {
			var err, err2 error
			err = s.addDelSnatPrefix(oldIpamPool, false /* isAdd */)
			err2 = s.addDelSnatPrefix(newIpamPool, true /* isAdd */)
			if err != nil || err2 != nil {
				return errors.Errorf("error updating snat prefix del:%s, add:%s", err, err2)
			}
			s.cniHandler.OnIpamConfChanged(oldIpamPool, newIpamPool)
			common.SendEvent(common.CalicoVppEvent{
				Type: common.IpamConfChanged,
				Old:  ipamPoolCopy(oldIpamPool),
				New:  ipamPoolCopy(newIpamPool),
			})
		}
	} else {
		s.log.Infof("Adding pool: %s, nat:%t", msg.GetId(), newIpamPool.GetMasquerade())
		s.cache.IPPoolMap[msg.GetId()] = newIpamPool
		s.log.Debugf("Pool %v Added, handler called", msg)
		err = s.addDelSnatPrefix(newIpamPool, true /* isAdd */)
		if err != nil {
			return errors.Wrap(err, "error handling ipam add")
		}
		s.cniHandler.OnIpamConfChanged(nil /*old*/, newIpamPool)
		common.SendEvent(common.CalicoVppEvent{
			Type: common.IpamConfChanged,
			New:  ipamPoolCopy(newIpamPool),
		})
	}
	return nil
}

func (s *Server) handleIpamPoolRemove(msg *proto.IPAMPoolRemove) (err error) {
	if msg.GetId() == "" {
		s.log.Debugf("Empty pool")
		return nil
	}
	s.ippoolLock.Lock()
	defer s.ippoolLock.Unlock()
	oldIpamPool, found := s.cache.IPPoolMap[msg.GetId()]
	if found {
		delete(s.cache.IPPoolMap, msg.GetId())
		s.log.Infof("Deleting pool: %s", msg.GetId())
		s.log.Debugf("Pool %s deleted, handler called", oldIpamPool.Cidr)
		err = s.addDelSnatPrefix(oldIpamPool, false /* isAdd */)
		if err != nil {
			return errors.Wrap(err, "error handling ipam deletion")
		}
		common.SendEvent(common.CalicoVppEvent{
			Type: common.IpamConfChanged,
			Old:  ipamPoolCopy(oldIpamPool),
			New:  nil,
		})
		s.cniHandler.OnIpamConfChanged(oldIpamPool, nil /* new */)
	} else {
		s.log.Warnf("Deleting unknown ippool")
		return nil
	}
	return nil
}

func ipamPoolCopy(ipamPool *proto.IPAMPool) *proto.IPAMPool {
	if ipamPool != nil {
		return &proto.IPAMPool{
			Cidr:       ipamPool.Cidr,
			Masquerade: ipamPool.Masquerade,
			IpipMode:   ipamPool.IpipMode,
			VxlanMode:  ipamPool.VxlanMode,
		}
	}
	return nil
}

// Compare only the fields that make a difference for this agent i.e. the fields that have an impact on routing
func ipamPoolEquals(a *proto.IPAMPool, b *proto.IPAMPool) bool {
	if (a == nil || b == nil) && a != b {
		return false
	}
	if a.Cidr != b.Cidr {
		return false
	}
	if a.IpipMode != b.IpipMode {
		return false
	}
	if a.VxlanMode != b.VxlanMode {
		return false
	}
	return true
}

// addDelSnatPrefix configures IP Pool prefixes so that we don't source-NAT the packets going
// to these addresses. All the IP Pools prefixes are configured that way so that pod <-> pod
// communications are never source-nated in the cluster
// Note(aloaugus) - I think the iptables dataplane behaves differently and uses the k8s level
// pod CIDR for this rather than the individual pool prefixes
func (s *Server) addDelSnatPrefix(pool *proto.IPAMPool, isAdd bool) (err error) {
	_, ipNet, err := net.ParseCIDR(pool.GetCidr())
	if err != nil {
		return errors.Wrapf(err, "Couldn't parse pool CIDR %s", pool.Cidr)
	}
	err = s.vpp.CnatAddDelSnatPrefix(ipNet, isAdd)
	if err != nil {
		return errors.Wrapf(err, "Couldn't configure SNAT prefix")
	}
	return nil
}
