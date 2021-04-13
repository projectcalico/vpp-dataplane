// Copyright (C) 2021 Cisco Systems Inc.
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

package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func network(address string) *net.IPNet {
	_, n, _ := net.ParseCIDR(address)
	return n
}

var (
	gw               = net.ParseIP("192.168.2.1")
	net0             = network("192.168.2.1/32")
	net1             = network("192.168.2.0/24")
	net2             = network("192.168.3.0/24")
	net3             = network("10.8.0.0/16")
	deflt *net.IPNet = nil
)

// LinkIndex is the target position of the route in sorted order
var routesLists = [][]netlink.Route{
	{
		netlink.Route{LinkIndex: 3, Dst: deflt, Gw: gw},
		netlink.Route{LinkIndex: 1, Dst: net2, Gw: gw},
		netlink.Route{LinkIndex: 2, Dst: net3, Gw: gw},
		netlink.Route{LinkIndex: 0, Dst: net0, Gw: nil},
	},
}

func TestRouteSort(t *testing.T) {
	for _, rl := range routesLists {
		c := InterfaceConfig{Routes: rl}
		c.SortRoutes()
		for i, r := range c.Routes {
			assert.Equal(t, r.LinkIndex, i)
		}
	}
}
