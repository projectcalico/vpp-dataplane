// Copyright (C) 2019 Cisco Systems Inc.
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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type FlatL3Provider struct {
	*ConnectivityProviderData
}

func getRoutePaths(addr net.IP) []types.RoutePath {
	return []types.RoutePath{{
		Gw:        addr,
		SwIfIndex: vpplink.AnyInterface,
		Table:     0,
	}}
}

func (p *FlatL3Provider) OnVppRestart() {
	/* Nothing to do */
}

func (p *FlatL3Provider) RescanState() {
	/* Nothing to do */
}

func (p *FlatL3Provider) Enabled() bool {
	return true
}

func NewFlatL3Provider(d *ConnectivityProviderData) *FlatL3Provider {
	return &FlatL3Provider{d}
}

func (p *FlatL3Provider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Printf("adding route %s to VPP", cn.Dst.String())
	paths := getRoutePaths(cn.NextHop)
	err := p.vpp.RouteAdd(&types.Route{
		Paths: paths,
		Dst:   &cn.Dst,
	})
	return errors.Wrap(err, "error replacing route")
}

func (p *FlatL3Provider) DelConnectivity(cn *common.NodeConnectivity) error {
	p.log.Debugf("removing route %s from VPP", cn.Dst.String())
	paths := getRoutePaths(cn.NextHop)
	err := p.vpp.RouteDel(&types.Route{
		Paths: paths,
		Dst:   &cn.Dst,
	})
	return errors.Wrap(err, "error deleting route")
}
