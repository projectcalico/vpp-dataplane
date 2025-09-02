// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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

package connectivity

import (
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
)

const (
	FLAT      = "flat"
	IPSEC     = "ipsec"
	VXLAN     = "vxlan"
	IPIP      = "ipip"
	WIREGUARD = "wireguard"
	SRv6      = "srv6"
)

// ConnectivityProvider configures VPP to have proper connectivity to other K8s nodes.
// Different implementations can connect VPP with VPP in other K8s node by using different networking
// technologies (VXLAN, SRv6,...).
type ConnectivityProvider interface {
	AddConnectivity(cn *common.NodeConnectivity) error
	DelConnectivity(cn *common.NodeConnectivity) error
	// RescanState check current state in VPP and updates local cache
	RescanState()
	// Enabled checks whether the ConnectivityProvider is enabled in the config
	Enabled(cn *common.NodeConnectivity) bool
	EnableDisable(isEnable bool)
}

func getNodeByIP(cache *cache.Cache, addr net.IP) *common.LocalNodeSpec {
	ns, found := cache.NodeByAddr[addr.String()]
	if !found {
		return nil
	}
	return &ns
}

func getNodeIPs(cache *cache.Cache) (ip4 *net.IP, ip6 *net.IP) {
	ip4, ip6 = common.GetBGPSpecAddresses(cache.NodeBGPSpec)
	return ip4, ip6
}
