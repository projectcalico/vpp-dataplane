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

	felixConfig "github.com/projectcalico/calico/felix/config"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

const (
	FLAT      = "flat"
	IPSEC     = "ipsec"
	VXLAN     = "vxlan"
	IPIP      = "ipip"
	WIREGUARD = "wireguard"
	SRv6      = "srv6"
)

type ConnectivityProviderData struct {
	vpp    *vpplink.VppLink
	log    *logrus.Entry
	server *ConnectivityServer
}

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

func (p *ConnectivityProviderData) GetNodeByIP(addr net.IP) *common.LocalNodeSpec {
	return p.server.GetNodeByIP(addr)
}
func (p *ConnectivityProviderData) GetNodeIPs() (*net.IP, *net.IP) {
	return p.server.GetNodeIPs()
}
func (p *ConnectivityProviderData) Clientv3() calicov3cli.Interface {
	return p.server.Clientv3
}
func (p *ConnectivityProviderData) GetFelixConfig() *felixConfig.Config {
	return p.server.felixConfig
}

func NewConnectivityProviderData(
	vpp *vpplink.VppLink,
	server *ConnectivityServer,
	log *logrus.Entry,
) *ConnectivityProviderData {
	return &ConnectivityProviderData{
		vpp:    vpp,
		log:    log,
		server: server,
	}
}
