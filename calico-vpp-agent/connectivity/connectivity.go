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

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
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
	ipv6   *net.IP
	ipv4   *net.IP
	server *ConnectivityServer
}

type ConnectivityProvider interface {
	AddConnectivity(cn *common.NodeConnectivity) error
	DelConnectivity(cn *common.NodeConnectivity) error
	/* Called when VPP signals us that it has restarted */
	OnVppRestart()
	/* Check current state in VPP and update local cache */
	RescanState()
	/* is it enabled in the config ? */
	Enabled() bool
}

func (p *ConnectivityProviderData) GetNodeByIp(addr net.IP) *oldv3.Node {
	return p.server.GetNodeByIp(addr)
}
func (p *ConnectivityProviderData) GetNodeIPs() (*net.IP, *net.IP) {
	return p.server.GetNodeIPs()
}
func (p *ConnectivityProviderData) Clientv3() calicov3cli.Interface {
	return p.server.Clientv3
}
func (p *ConnectivityProviderData) GetFelixConfig() *calicov3.FelixConfigurationSpec {
	return &p.server.felixConfiguration
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
