// Copyright (C) 2024 Cisco Systems Inc.
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

package framework

import (
	"net"

	. "github.com/onsi/gomega"
)

// parseMAC is a helper to parse MAC address
func parseMAC(macStr string) net.HardwareAddr {
	mac, err := net.ParseMAC(macStr)
	Expect(err).ToNot(HaveOccurred(), "failed to parse MAC address: %s", macStr)
	return mac
}

// parseIPNet is a helper to parse CIDR notation
// Returns an IPNet with the IP from the CIDR (not the network address)
func parseIPNet(cidr string) *net.IPNet {
	ip, ipNet, err := net.ParseCIDR(cidr)
	Expect(err).ToNot(HaveOccurred(), "failed to parse CIDR: %s", cidr)
	// net.ParseCIDR returns the network address in ipNet.IP, but we want the host IP
	ipNet.IP = ip
	return ipNet
}

// ParseIP is a helper to parse IP address
func ParseIP(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	Expect(ip).ToNot(BeNil(), "failed to parse IP address: %s", ipStr)
	return ip
}

// IPNet creates an IPNet from CIDR string
func IPNet(cidr string) *net.IPNet {
	return parseIPNet(cidr)
}

// CreateTapInterface is a helper to create a TAP interface for testing
func CreateTapInterface(vpp interface{}, name string, address string) struct{ SwIfIndex uint32 } {
	// This is a simplified helper - implement based on your vpplink API
	return struct{ SwIfIndex uint32 }{SwIfIndex: 1}
}

// Mac creates a hardware address from string
func Mac(macStr string) net.HardwareAddr {
	return parseMAC(macStr)
}
