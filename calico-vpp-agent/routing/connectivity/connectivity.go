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
	"fmt"
	"net"

	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicov3cli "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

const (
	FLAT      = "flat"
	IPSEC     = "ipsec"
	VXLAN     = "vxlan"
	IPIP      = "ipip"
	WIREGUARD = "wireguard"
)

type NodeConnectivity struct {
	Dst     net.IPNet
	NextHop net.IP
}

func (cn *NodeConnectivity) String() string {
	return fmt.Sprintf("%s-%s", cn.Dst.String(), cn.NextHop.String())
}

type ConnectivityProvider interface {
	AddConnectivity(cn *NodeConnectivity) error
	DelConnectivity(cn *NodeConnectivity) error
	/* Called when VPP signals us that it has restarted */
	OnVppRestart()
	/* Check current state in VPP and update local cache */
	RescanState()
	/* is it enabled in the config ? */
	Enabled() bool
}

type RoutingServerUtils interface {
	GetNodeByIp(addr net.IP) *calicov3.NodeSpec
	GetNodeNameByIp(addr net.IP) string
	GetNodeIP(isv6 bool) net.IP
	GetNodeIPNet(isv6 bool) *net.IPNet
	Clientv3() calicov3cli.Interface
	GetFelixConfig() *calicov3.FelixConfigurationSpec
}

type ConnectivityProviderData struct {
	vpp       *vpplink.VppLink
	log       *logrus.Entry
	ipv6      *net.IP
	ipv4      *net.IP
	felixConf *calicov3.FelixConfigurationSpec
	server    RoutingServerUtils
}

func NewConnectivityProviderData(
	vpp *vpplink.VppLink,
	log *logrus.Entry,
	server RoutingServerUtils,
) *ConnectivityProviderData {
	return &ConnectivityProviderData{
		vpp:       vpp,
		log:       log,
		server:    server,
	}
}
