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

package cache

import (
	"net"

	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type Cache struct {
	log *logrus.Entry

	FelixConfig                      *felixConfig.Config
	NodeByAddr                       map[string]common.LocalNodeSpec
	NodeBGPSpec                      *common.LocalNodeSpec
	Networks                         map[uint32]*common.NetworkDefinition
	NetworkDefinitions               map[string]*common.NetworkDefinition
	IPPoolMap                        map[string]*proto.IPAMPool
	RedirectToHostClassifyTableIndex uint32
	VppAvailableBuffers              uint64
	NumDataThreads                   int
	NodeStatesByName                 map[string]*common.LocalNodeSpec
	BGPConf                          *calicov3.BGPConfigurationSpec
}

func NewCache(log *logrus.Entry) *Cache {
	return &Cache{
		log:                              log,
		NodeByAddr:                       make(map[string]common.LocalNodeSpec),
		FelixConfig:                      felixConfig.New(),
		Networks:                         make(map[uint32]*common.NetworkDefinition),
		NetworkDefinitions:               make(map[string]*common.NetworkDefinition),
		IPPoolMap:                        make(map[string]*proto.IPAMPool),
		RedirectToHostClassifyTableIndex: types.InvalidID,
		NodeStatesByName:                 make(map[string]*common.LocalNodeSpec),
	}
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (cache *Cache) GetPrefixIPPool(prefix *net.IPNet) *proto.IPAMPool {
	for _, pool := range cache.IPPoolMap {
		in, err := ipamPoolContains(pool, prefix)
		if err != nil {
			cache.log.Warnf("ipamPoolContains errored: %v", err)
			continue
		}
		if in {
			return pool
		}
	}
	cache.log.Warnf("No pool found for %s", prefix)
	for k, pool := range cache.IPPoolMap {
		cache.log.Debugf("Available %s=%v", k, pool)
	}
	return nil
}

// ipamPoolContains returns true if the IPPool contains 'prefix'
func ipamPoolContains(pool *proto.IPAMPool, prefix *net.IPNet) (bool, error) {
	_, poolCIDR, _ := net.ParseCIDR(pool.GetCidr()) // this field is validated so this should never error
	poolCIDRLen, poolCIDRBits := poolCIDR.Mask.Size()
	prefixLen, prefixBits := prefix.Mask.Size()
	return poolCIDRBits == prefixBits && poolCIDR.Contains(prefix.IP) && prefixLen >= poolCIDRLen, nil
}

func (cache *Cache) GetNodeIP4() *net.IP {
	if cache.NodeBGPSpec != nil {
		if cache.NodeBGPSpec.IPv4Address != nil {
			return &cache.NodeBGPSpec.IPv4Address.IP
		}
	}
	return nil
}

func (cache *Cache) GetNodeIP6() *net.IP {
	if cache.NodeBGPSpec != nil {
		if cache.NodeBGPSpec.IPv6Address != nil {
			return &cache.NodeBGPSpec.IPv6Address.IP
		}
	}
	return nil
}

func (cache *Cache) GetNodeIPNet(isv6 bool) *net.IPNet {
	if cache.NodeBGPSpec != nil {
		if isv6 {
			return cache.NodeBGPSpec.IPv6Address
		} else {
			return cache.NodeBGPSpec.IPv4Address
		}
	}
	return nil
}
