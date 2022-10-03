// Copyright (c) 2022 Cisco and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mocks

import (
	"fmt"
	"net"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"gopkg.in/tomb.v2"
)

// IpamCacheStub is stub implementation of watchers.IpamCache.
type IpamCacheStub struct {
	ipPools map[string]*proto.IPAMPoolUpdate
}

// NewIpamCacheStub creates new IpamCacheStub instance
func NewIpamCacheStub() *IpamCacheStub {
	return &IpamCacheStub{
		ipPools: make(map[string]*proto.IPAMPoolUpdate),
	}
}

// GetPrefixIPPool returns cached IPPools for given prefixes for testing purposes. If no such IPPool exists,
// it is created. This function never runs out of IPPools
func (s *IpamCacheStub) GetPrefixIPPool(prefix *net.IPNet) *proto.IPAMPool {
	// get cached IPPool
	ipPool, found := s.ipPools[prefix.String()]
	if found {
		return ipPool.Pool
	}

	// create new IPPool and cache it
	ipPool = &proto.IPAMPoolUpdate{
		Id: fmt.Sprintf("ippool-for-testing-%s", prefix.String()),
		Pool: &proto.IPAMPool{
			Cidr: prefix.String(),
		},
	}
	/*ipPool = &calicov3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("ippool-for-testing-%s", prefix.String()),
		},
		Spec: calicov3.IPPoolSpec{
			CIDR: prefix.String(),
		},
	}*/
	s.ipPools[prefix.String()] = ipPool
	return ipPool.Pool
}

func (s *IpamCacheStub) SyncIPAM(t *tomb.Tomb) error {
	panic("not implemented")
}

func (s *IpamCacheStub) WaitReady() {
	panic("not implemented")
}

func (s *IpamCacheStub) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	return false
}

func (s *IpamCacheStub) AddPrefixIPPool(prefix *net.IPNet, ipPool *proto.IPAMPoolUpdate) {
	s.ipPools[prefix.String()] = ipPool
}
