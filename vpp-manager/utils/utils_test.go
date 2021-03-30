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

package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var incDecPairs = []struct{ low, high net.IP }{
	{net.ParseIP("192.168.2.0"), net.ParseIP("192.168.2.1")},
	{net.ParseIP("192.168.2.4"), net.ParseIP("192.168.2.5")},
	{net.ParseIP("192.168.2.255"), net.ParseIP("192.168.3.0")},
	{net.ParseIP("192.167.255.255"), net.ParseIP("192.168.0.0")},
	{net.ParseIP("9.255.255.255"), net.ParseIP("10.0.0.0")},
	{net.ParseIP("255.255.255.255"), net.ParseIP("0.0.0.0")},
	{net.ParseIP("fd00::1000"), net.ParseIP("fd00::1001")},
	{net.ParseIP("fd00::0fff"), net.ParseIP("fd00::1000")},
	{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), net.ParseIP("::")},
	{net.ParseIP("0:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), net.ParseIP("1::")},
}

func TestIncrementDecrement(t *testing.T) {
	for _, tc := range incDecPairs {
		assert.True(t, DecrementIP(tc.high).Equal(tc.low))
		assert.True(t, IncrementIP(tc.low).Equal(tc.high))
	}
}

func network(t *testing.T, address string) *net.IPNet {
	_, n, err := net.ParseCIDR(address)
	assert.NoError(t, err)
	return n
}

var networks = []struct {
	netAddr, brdAddr net.IP
	network          string
}{
	{net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), "10.0.0.1/24"},
	{net.ParseIP("0.0.0.0"), net.ParseIP("255.255.255.255"), "0.0.0.0/0"},
	{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255"), "192.168.123.123/16"},
	{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.0.63"), "192.168.0.0/26"},
	{net.ParseIP("::"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "::/0"},
	{net.ParseIP("fd01::"), net.ParseIP("fd01::ffff:ffff:ffff:ffff"), "fd01::1/64"},
	{net.ParseIP("fd01::"), net.ParseIP("fd01::3"), "fd01::1/126"},
}

func TestNetworkBroadcastAddr(t *testing.T) {
	for _, d := range networks {
		assert.True(t, NetworkAddr(network(t, d.network)).Equal(d.netAddr))
		assert.True(t, BroadcastAddr(network(t, d.network)).Equal(d.brdAddr))
	}
}
