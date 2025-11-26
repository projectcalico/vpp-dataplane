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
	"fmt"
	"net"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// VppAssertions provides assertion helpers for VPP state
type VppAssertions struct {
	vpp *vpplink.VppLink
}

// NewVppAssertions creates a new VppAssertions helper
func NewVppAssertions(vpp *vpplink.VppLink) *VppAssertions {
	return &VppAssertions{vpp: vpp}
}

// AssertInterfaceExists checks that an interface with the given tag exists
func (a *VppAssertions) AssertInterfaceExists(tag string) uint32 {
	swIfIndex, err := a.vpp.SearchInterfaceWithTag(tag)
	Expect(err).ToNot(HaveOccurred(), "failed to search for interface with tag: %s", tag)
	Expect(swIfIndex).ToNot(Equal(vpplink.InvalidSwIfIndex), "interface with tag %s not found", tag)
	Expect(swIfIndex).ToNot(BeZero(), "interface with tag %s has invalid index", tag)
	return swIfIndex
}

// AssertInterfaceHasIPAddress checks that an interface has the expected IP address
func (a *VppAssertions) AssertInterfaceHasIPAddress(swIfIndex uint32, expectedIP string) {
	// Parse the expected IP to determine if it's IPv4 or IPv6
	parsedIP := net.ParseIP(expectedIP)
	Expect(parsedIP).ToNot(BeNil(), "invalid IP address: %s", expectedIP)
	isIPv6 := parsedIP.To4() == nil

	// Check if interface is unnumbered first
	couples, err := a.vpp.InterfaceGetUnnumbered(swIfIndex)
	Expect(err).ToNot(HaveOccurred(), "failed to get unnumbered interface info")

	if len(couples) > 0 {
		// Interface is unnumbered, check the target interface
		addrList, err := a.vpp.AddrList(uint32(couples[0].IPSwIfIndex), isIPv6)
		Expect(err).ToNot(HaveOccurred(), "failed to get addresses for unnumbered interface")

		found := false
		for _, addr := range addrList {
			if addr.IPNet.IP.Equal(parsedIP) {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "interface does not have expected IP address %s", expectedIP)
	} else {
		// Check direct addresses
		addrList, err := a.vpp.AddrList(swIfIndex, isIPv6)
		Expect(err).ToNot(HaveOccurred(), "failed to get interface addresses")

		found := false
		for _, addr := range addrList {
			if addr.IPNet.IP.Equal(parsedIP) {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "interface does not have expected IP address %s", expectedIP)
	}
}

// AssertInterfaceHasMTU checks that an interface has the expected MTU
func (a *VppAssertions) AssertInterfaceHasMTU(swIfIndex uint32, expectedMTU int) {
	details, err := a.vpp.GetInterfaceDetails(swIfIndex)
	Expect(err).ToNot(HaveOccurred(), "failed to get interface details")
	Expect(int(details.Mtu[0])).To(Equal(expectedMTU), "interface MTU mismatch")
}

// AssertInterfaceIsUp checks that an interface is administratively up
func (a *VppAssertions) AssertInterfaceIsUp(swIfIndex uint32) {
	details, err := a.vpp.GetInterfaceDetails(swIfIndex)
	Expect(err).ToNot(HaveOccurred(), "failed to get interface details")
	Expect(details.IsUp).To(BeTrue(), "interface is not admin up")
}

// AssertInterfaceGSO checks that GSO is enabled on an interface
func (a *VppAssertions) AssertInterfaceGSO(swIfIndex uint32) {
	featuresStr, err := a.vpp.RunCli(fmt.Sprintf("sh interface %d features", swIfIndex))
	Expect(err).ToNot(HaveOccurred(), "failed to get interface features")

	featuresStr = strings.ToLower(featuresStr)
	gsoFeatures := []string{"gso-ip4", "gso-ip6", "gso-l2-ip4", "gso-l2-ip6"}
	for _, gsoStr := range gsoFeatures {
		Expect(featuresStr).To(ContainSubstring(gsoStr), "GSO feature %s not enabled", gsoStr)
	}
}

// AssertInterfaceCNAT checks that CNAT is enabled on an interface
func (a *VppAssertions) AssertInterfaceCNAT(swIfIndex uint32) {
	featuresStr, err := a.vpp.RunCli(fmt.Sprintf("sh interface %d features", swIfIndex))
	Expect(err).ToNot(HaveOccurred(), "failed to get interface features")

	featuresStr = strings.ToLower(featuresStr)
	cnatFeatures := []string{"cnat-input-ip4", "cnat-input-ip6", "cnat-output-ip4", "cnat-output-ip6"}
	for _, cnatStr := range cnatFeatures {
		Expect(featuresStr).To(ContainSubstring(cnatStr), "CNAT feature %s not enabled", cnatStr)
	}
}

// AssertRouteExists checks that a specific route exists in the specified VRF
func (a *VppAssertions) AssertRouteExists(vrfID uint32, dstCIDR string, nextHop string) {
	routes, err := a.vpp.GetRoutes(vrfID, false)
	Expect(err).ToNot(HaveOccurred(), "failed to get routes")

	expectedRoute := types.Route{
		Dst: IPNet(dstCIDR),
		Paths: []types.RoutePath{{
			Gw: net.ParseIP(nextHop),
		}},
		Table: vrfID,
	}

	found := false
	for _, route := range routes {
		if route.Dst.String() == expectedRoute.Dst.String() {
			for _, path := range route.Paths {
				if path.Gw.Equal(expectedRoute.Paths[0].Gw) {
					found = true
					break
				}
			}
		}
	}
	Expect(found).To(BeTrue(), "route to %s via %s not found in VRF %d", dstCIDR, nextHop, vrfID)
}

// AssertRouteViaInterface checks that a route exists via a specific interface
func (a *VppAssertions) AssertRouteViaInterface(vrfID uint32, dstCIDR string, swIfIndex uint32) {
	routes, err := a.vpp.GetRoutes(vrfID, false)
	Expect(err).ToNot(HaveOccurred(), "failed to get routes")

	found := false
	for _, route := range routes {
		if route.Dst.String() == dstCIDR {
			for _, path := range route.Paths {
				if path.SwIfIndex == swIfIndex {
					found = true
					break
				}
			}
		}
	}
	Expect(found).To(BeTrue(), "route to %s via interface %d not found in VRF %d", dstCIDR, swIfIndex, vrfID)
}

// AssertVRFExists checks that a VRF with the given ID exists
func (a *VppAssertions) AssertVRFExists(vrfID uint32) {
	vrfs, err := a.vpp.ListVRFs()
	Expect(err).ToNot(HaveOccurred(), "failed to list VRFs")

	found := false
	for _, vrf := range vrfs {
		if vrf.VrfID == vrfID {
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(), "VRF %d not found", vrfID)
}

// AssertVRFExistsByName checks that a VRF with the given name exists and returns its ID
func (a *VppAssertions) AssertVRFExistsByName(name string) uint32 {
	vrfs, err := a.vpp.ListVRFs()
	Expect(err).ToNot(HaveOccurred(), "failed to list VRFs")

	for _, vrf := range vrfs {
		if vrf.Name == name {
			return vrf.VrfID
		}
	}
	Fail(fmt.Sprintf("VRF with name %s not found", name))
	return 0
}

// AssertIPIPTunnelExists checks that an IPIP tunnel exists with given parameters
func (a *VppAssertions) AssertIPIPTunnelExists(src, dst string) uint32 {
	tunnels, err := a.vpp.ListIPIPTunnels()
	Expect(err).ToNot(HaveOccurred(), "failed to list IPIP tunnels")

	srcIP := net.ParseIP(src).To4()
	dstIP := net.ParseIP(dst).To4()

	for _, tunnel := range tunnels {
		if tunnel.Src.Equal(srcIP) && tunnel.Dst.Equal(dstIP) {
			return tunnel.SwIfIndex
		}
	}
	Fail(fmt.Sprintf("IPIP tunnel from %s to %s not found", src, dst))
	return 0
}

// AssertMemifInterfaceExists checks that a memif interface exists
func (a *VppAssertions) AssertMemifInterfaceExists(swIfIndex uint32) {
	memifs, err := a.vpp.ListMemifInterfaces()
	Expect(err).ToNot(HaveOccurred(), "failed to list memif interfaces")

	found := false
	for _, memif := range memifs {
		if memif.SwIfIndex == swIfIndex {
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(), "memif interface %d not found", swIfIndex)
}

// AssertUnnumberedInterface checks that an interface is unnumbered and gets IP from the expected interface
func (a *VppAssertions) AssertUnnumberedInterface(swIfIndex uint32, ipSwIfIndex uint32) {
	couples, err := a.vpp.InterfaceGetUnnumbered(swIfIndex)
	Expect(err).ToNot(HaveOccurred(), "failed to get unnumbered interface info")
	Expect(couples).ToNot(BeEmpty(), "interface is not unnumbered")
	Expect(uint32(couples[0].IPSwIfIndex)).To(Equal(ipSwIfIndex), "unnumbered interface gets IP from wrong interface")
}

// AssertRoutesContain checks that routes contain expected entries
func (a *VppAssertions) AssertRoutesContain(vrfID uint32, isIP6 bool, expectedRoutes ...types.Route) {
	routes, err := a.vpp.GetRoutes(vrfID, isIP6)
	Expect(err).ToNot(HaveOccurred(), "failed to get routes from VRF %d", vrfID)

	for _, expected := range expectedRoutes {
		found := false
		for _, route := range routes {
			if route.Dst.String() == expected.Dst.String() {
				// Check if paths match
				for _, expectedPath := range expected.Paths {
					for _, routePath := range route.Paths {
						if (expectedPath.Gw == nil || routePath.Gw.Equal(expectedPath.Gw)) &&
							(expectedPath.SwIfIndex == 0 || routePath.SwIfIndex == expectedPath.SwIfIndex) {
							found = true
							break
						}
					}
					if found {
						break
					}
				}
			}
			if found {
				break
			}
		}
		Expect(found).To(BeTrue(), "expected route to %s not found in VRF %d", expected.Dst.String(), vrfID)
	}
}

// GetInterfaceByTag returns the interface SwIfIndex for a given tag
func (a *VppAssertions) GetInterfaceByTag(tag string) (uint32, error) {
	return a.vpp.SearchInterfaceWithTag(tag)
}
