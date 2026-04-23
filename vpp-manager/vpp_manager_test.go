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

package main

import (
	"fmt"
	"net"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/testutils"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	VppImageEnv  = "VPP_IMAGE"
	VppBinaryEnv = "VPP_BINARY"
)

var (
	vppImage  string
	vppBinary string
	testLog   *logrus.Logger
)

func TestVppManager(t *testing.T) {
	// Skip if VPP_IMAGE is not set (needed for integration tests)
	_, hasImage := os.LookupEnv(VppImageEnv)
	if !hasImage {
		t.Skip("Skipping vpp-manager integration tests (VPP_IMAGE not set)")
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "VPP Manager Test Suite")
}

var _ = BeforeSuite(func() {
	var ok bool
	vppImage, ok = os.LookupEnv(VppImageEnv)
	Expect(ok).To(BeTrue(), "VPP_IMAGE environment variable must be set")
	Expect(vppImage).ToNot(BeEmpty(), "VPP_IMAGE cannot be empty")

	vppBinary, ok = os.LookupEnv(VppBinaryEnv)
	if !ok || vppBinary == "" {
		vppBinary = "/usr/bin/vpp"
	}

	testLog = logrus.New()
	testLog.SetLevel(logrus.InfoLevel)

	testutils.LogInfo("Using VPP image: %s", vppImage)
	testutils.LogInfo("Using VPP binary: %s", vppBinary)
})

var _ = Describe("vpp-manager", func() {
	var vppFixture *testutils.VppFixture

	BeforeEach(func() {
		vppFixture = &testutils.VppFixture{
			Config: testutils.DefaultVppConfig(),
		}
		vppFixture.Setup("vpp-manager-test", vppImage, vppBinary, testLog)
	})

	AfterEach(func() {
		if vppFixture != nil {
			vppFixture.Teardown()
		}
	})

	Context("VppRunner.allocateStaticVRFs", func() {
		// This test calls the VppRunner.allocateStaticVRFs() method
		// from vpp_runner.go to verify VRF allocation works correctly

		It("should create punt and pod VRFs for IPv4 and IPv6", func() {
			testutils.LogSection("Testing VppRunner.allocateStaticVRFs()")
			vpp := vppFixture.Instance.GetVppLink()

			// Create a VppRunner instance with the test VPP connection
			runner := &VppRunner{
				params: &config.VppManagerParams{},
				conf:   []*config.LinuxInterfaceState{},
				vpp:    vpp,
			}

			testutils.LogStep("Calling runner.allocateStaticVRFs()")
			err := runner.allocateStaticVRFs()
			Expect(err).ToNot(HaveOccurred(), "allocateStaticVRFs() failed")
			testutils.LogSuccess("allocateStaticVRFs() completed successfully")

			// Verify the VRFs were created in VPP
			testutils.LogStep("Verifying VRFs were created")
			fibOutput, err := vpp.RunCli("show ip fib summary")
			Expect(err).ToNot(HaveOccurred())
			testutils.LogInfo("VRF summary (IPv4):\n%s", fibOutput)

			// Check for punt table by name
			Expect(fibOutput).To(ContainSubstring("punt-table-ip4"),
				"punt VRF should exist")
			testutils.LogSuccess("Punt table (punt-table-ip4) created")

			// Check for pod VRF by name
			Expect(fibOutput).To(ContainSubstring("calico-pods-ip4"),
				"pod VRF should exist")
			testutils.LogSuccess("Pod VRF (calico-pods-ip4) created")

			// Check IPv6 VRFs
			fib6Output, err := vpp.RunCli("show ip6 fib summary")
			Expect(err).ToNot(HaveOccurred())
			testutils.LogInfo("VRF summary (IPv6):\n%s", fib6Output)

			Expect(fib6Output).To(ContainSubstring("punt-table-ip6"),
				"punt VRF (v6) should exist")
			testutils.LogSuccess("Punt table v6 (punt-table-ip6) created")

			Expect(fib6Output).To(ContainSubstring("calico-pods-ip6"),
				"pod VRF (v6) should exist")
			testutils.LogSuccess("Pod VRF v6 (calico-pods-ip6) created")

			testutils.LogSuccess("VppRunner.allocateStaticVRFs() test passed")
		})
	})

	Context("VppRunner.AllocatePhysicalNetworkVRFs", func() {
		// This test calls the VppRunner.AllocatePhysicalNetworkVRFs() method
		// from vpp_runner.go to verify physical network VRF allocation

		It("should create VRFs for a physical network", func() {
			testutils.LogSection("Testing VppRunner.AllocatePhysicalNetworkVRFs()")
			vpp := vppFixture.Instance.GetVppLink()

			// Reset physical networks map for clean test
			config.Info.PhysicalNets = make(map[string]config.PhysicalNetwork)

			// Create a VppRunner instance with the test VPP connection
			runner := &VppRunner{
				params: &config.VppManagerParams{},
				conf:   []*config.LinuxInterfaceState{},
				vpp:    vpp,
			}

			testPhyNetName := "test-physical-net"

			testutils.LogStep("Calling runner.AllocatePhysicalNetworkVRFs(%q)", testPhyNetName)
			err := runner.AllocatePhysicalNetworkVRFs(testPhyNetName)
			Expect(err).ToNot(HaveOccurred(), "AllocatePhysicalNetworkVRFs() failed")
			testutils.LogSuccess("AllocatePhysicalNetworkVRFs() completed successfully")

			// Verify the physical network was registered in config.Info
			testutils.LogStep("Verifying physical network registered in config.Info")
			phyNet, exists := config.Info.PhysicalNets[testPhyNetName]
			Expect(exists).To(BeTrue(), "physical network should be registered")
			Expect(phyNet.VrfID).ToNot(BeZero(), "VrfID should be allocated")
			Expect(phyNet.PodVrfID).ToNot(BeZero(), "PodVrfID should be allocated")
			testutils.LogSuccess("Physical network registered: VrfID=%d, PodVrfID=%d",
				phyNet.VrfID, phyNet.PodVrfID)

			// Verify VRFs were created in VPP
			testutils.LogStep("Verifying VRFs created in VPP")
			fibOutput, err := vpp.RunCli("show ip fib summary")
			Expect(err).ToNot(HaveOccurred())
			testutils.LogInfo("VRF summary:\n%s", fibOutput)

			Expect(fibOutput).To(ContainSubstring(fmt.Sprintf("physical-net-%s-ip4", testPhyNetName)),
				"physical network VRF should exist in VPP")
			testutils.LogSuccess("Physical network VRF (physical-net-%s-ip4) exists", testPhyNetName)

			Expect(fibOutput).To(ContainSubstring(fmt.Sprintf("calico-pods-%s-ip4", testPhyNetName)),
				"pod VRF for physical network should exist in VPP")
			testutils.LogSuccess("Pod VRF (calico-pods-%s-ip4) exists", testPhyNetName)

			testutils.LogSuccess("VppRunner.AllocatePhysicalNetworkVRFs() test passed")
		})
	})

	Context("VPP Configuration", func() {
		It("should verify VPP buffer and plugin configuration", func() {
			testutils.LogSection("Testing VPP buffer and plugin configuration")
			vpp := vppFixture.Instance.GetVppLink()

			// Check buffer configuration via CLI
			testutils.LogStep("Checking VPP buffer allocation via CLI")
			bufferOutput, err := vpp.RunCli("show buffers")
			Expect(err).ToNot(HaveOccurred(), "failed to get buffer info")
			Expect(bufferOutput).ToNot(BeEmpty(), "empty buffer output")
			testutils.LogInfo("Buffer summary:\n%s", bufferOutput)

			// Verify buffers are allocated
			testutils.LogStep("Verifying buffers are allocated")
			Expect(bufferOutput).To(MatchRegexp("(?i)avail"), "no available buffers")
			testutils.LogSuccess("VPP buffers allocated correctly")

			// Check plugin configuration
			testutils.LogStep("Checking loaded VPP plugins")
			pluginOutput, err := vpp.RunCli("show plugins")
			Expect(err).ToNot(HaveOccurred(), "failed to get plugin info")

			// Check that dispatch_trace_plugin plugin is loaded
			testutils.LogStep("Verifying dispatch_trace_plugin is loaded")
			Expect(pluginOutput).To(ContainSubstring("dispatch_trace_plugin.so"),
				"dispatch_trace_plugin plugin not loaded")
			testutils.LogSuccess("dispatch_trace_plugin.so loaded")

			// Check that DPDK plugin is disabled
			testutils.LogStep("Verifying dpdk_plugin is disabled")
			Expect(pluginOutput).ToNot(ContainSubstring("dpdk_plugin.so"),
				"dpdk plugin should be disabled")
			testutils.LogSuccess("dpdk_plugin.so disabled")

			testutils.LogSuccess("VPP configuration test passed")
		})
	})

	Context("Interface Configuration", func() {
		// NOTE: We cannot directly test VppRunner.configureVppUplinkInterface() in a container
		// environment because it creates a TAP with HostNamespace:"pid:1" that requires access
		// to the host's PID 1 network namespace. In a Docker container, pid:1 refers to the
		// container's init() process, not the host, causing the Linux-side tap setup to fail!
		//
		// This test verifies the VPP-side operations that configureVppUplinkInterface() performs:
		// - VRF allocation (via allocateStaticVRFs)
		// - Interface address configuration (AddInterfaceAddress)
		// - Interface state management (InterfaceAdminUp)
		It("should configure uplink interface addresses", func() {
			testutils.LogSection("Testing uplink interface address configuration")
			testutils.LogInfo("NOTE: This only tests a subset of VppRunner.configureVppUplinkInterface()")
			vpp := vppFixture.Instance.GetVppLink()

			// Create VRFs using VppRunner method
			testutils.LogStep("Setting up prerequisite VRFs via VppRunner.allocateStaticVRFs()")
			runner := &VppRunner{
				params: &config.VppManagerParams{},
				conf:   []*config.LinuxInterfaceState{},
				vpp:    vpp,
			}
			err := runner.allocateStaticVRFs()
			Expect(err).ToNot(HaveOccurred(), "allocateStaticVRFs() failed")
			testutils.LogSuccess("Static VRFs created via VppRunner")

			// Create a TAP interface to simulate an uplink interface
			testutils.LogStep("Creating TAP interface to simulate uplink")
			swIfIndex, err := vpp.CreateTapV2(&types.TapV2{
				GenericVppInterface: types.GenericVppInterface{
					HostInterfaceName: "uplink-tap",
					HardwareAddr:      testutils.ParseMAC("aa:bb:cc:dd:ee:01"),
				},
				Tag:            "test-uplink",
				Flags:          types.TapFlagNone,
				HostMtu:        1500,
				HostMacAddress: testutils.ParseMAC("aa:bb:cc:dd:ee:02"),
			})
			Expect(err).ToNot(HaveOccurred(), "failed to create TAP interface")
			testutils.LogSuccess("TAP interface created (swIfIndex: %d)", swIfIndex)

			// Test address configuration on uplink interface
			testutils.LogStep("Adding IPv4 address to uplink")
			testIPv4 := &net.IPNet{IP: net.ParseIP("192.168.100.1"), Mask: net.CIDRMask(24, 32)}
			err = vpp.AddInterfaceAddress(swIfIndex, testIPv4)
			Expect(err).ToNot(HaveOccurred(), "failed to add IPv4 address")

			testutils.LogStep("Adding IPv6 address to uplink")
			testIPv6 := &net.IPNet{IP: net.ParseIP("fd00:100::1"), Mask: net.CIDRMask(64, 128)}
			err = vpp.AddInterfaceAddress(swIfIndex, testIPv6)
			Expect(err).ToNot(HaveOccurred(), "failed to add IPv6 address")

			// Verify addresses were added
			testutils.LogStep("Verifying IPv4 addresses")
			ipv4Addrs, err := vpp.AddrList(swIfIndex, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(ipv4Addrs)).To(BeNumerically(">=", 1), "should have at least 1 IPv4 address")
			testutils.LogSuccess("Found %d IPv4 addresses", len(ipv4Addrs))

			testutils.LogStep("Verifying IPv6 addresses")
			ipv6Addrs, err := vpp.AddrList(swIfIndex, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(ipv6Addrs)).To(BeNumerically(">=", 1), "should have at least 1 IPv6 address")
			testutils.LogSuccess("Found %d IPv6 addresses", len(ipv6Addrs))

			// Bring interface up
			testutils.LogStep("Bringing interface up in VPP")
			err = vpp.InterfaceAdminUp(swIfIndex)
			Expect(err).ToNot(HaveOccurred())
			testutils.LogSuccess("Interface is up")

			// Verify interface state
			testutils.LogStep("Verifying interface details")
			details, err := vpp.GetInterfaceDetails(swIfIndex)
			Expect(err).ToNot(HaveOccurred())
			Expect(details.IsUp).To(BeTrue(), "interface should be up")
			testutils.LogSuccess("Interface %s is up (mtu: %v)", details.Name, details.Mtu)

			testutils.LogSuccess("Uplink interface address configuration test passed")
		})

		It("should create TAP interface", func() {
			testutils.LogSection("Testing TAP interface creation")
			vpp := vppFixture.Instance.GetVppLink()

			// Create TAP interface
			testutils.LogStep("Creating TAP interface")
			tapSwIfIndex, err := vpp.CreateTapV2(&types.TapV2{
				GenericVppInterface: types.GenericVppInterface{
					HostInterfaceName: "tap-test",
					HardwareAddr:      testutils.ParseMAC("aa:bb:cc:dd:ee:01"),
				},
				Tag:            "host-tap-test",
				Flags:          types.TapFlagNone,
				HostMtu:        1500,
				HostMacAddress: testutils.ParseMAC("aa:bb:cc:dd:ee:02"),
			})
			Expect(err).ToNot(HaveOccurred(), "failed to create TAP interface")
			testutils.LogSuccess("TAP interface created (swIfIndex: %d)", tapSwIfIndex)

			// Set interface up
			testutils.LogStep("Setting TAP interface up")
			err = vpp.InterfaceAdminUp(tapSwIfIndex)
			Expect(err).ToNot(HaveOccurred())
			testutils.LogSuccess("TAP interface is up")

			// Verify interface exists
			testutils.LogStep("Verifying TAP interface details")
			details, err := vpp.GetInterfaceDetails(tapSwIfIndex)
			Expect(err).ToNot(HaveOccurred())
			Expect(details.IsUp).To(BeTrue())
			testutils.LogSuccess("TAP interface %s verified", details.Name)

			testutils.LogSuccess("TAP interface creation test passed")
		})

		It("should create AF_PACKET interface", func() {
			testutils.LogSection("Testing AF_PACKET interface creation")
			vpp := vppFixture.Instance.GetVppLink()

			// Create a veth pair first
			testutils.LogStep("Creating veth pair (veth0 <-> veth1)")
			_, err := vppFixture.Instance.Exec("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
			Expect(err).ToNot(HaveOccurred(), "failed to create veth pair")

			testutils.LogStep("Bringing veth0 up")
			_, err = vppFixture.Instance.Exec("ip", "link", "set", "veth0", "up")
			Expect(err).ToNot(HaveOccurred(), "failed to bring up veth0")
			testutils.LogSuccess("Host veth pair created")

			// Create AF_PACKET interface in VPP
			testutils.LogStep("Creating AF_PACKET interface in VPP for veth0")
			swIfIndex, err := vpp.CreateAfPacket(&types.AfPacketInterface{
				GenericVppInterface: types.GenericVppInterface{
					HostInterfaceName: "veth0",
				},
			})
			Expect(err).ToNot(HaveOccurred(), "failed to create AF_PACKET interface")
			Expect(swIfIndex).ToNot(BeZero(), "invalid AF_PACKET interface index")
			testutils.LogSuccess("AF_PACKET interface created (swIfIndex: %d)", swIfIndex)

			// Bring interface up
			testutils.LogStep("Bringing AF_PACKET interface up in VPP")
			err = vpp.InterfaceAdminUp(swIfIndex)
			Expect(err).ToNot(HaveOccurred(), "failed to bring interface up")

			// Verify interface exists and is up
			testutils.LogStep("Verifying interface is up")
			assertions := testutils.NewVppAssertions(vpp)
			assertions.AssertInterfaceIsUp(swIfIndex)
			testutils.LogSuccess("AF_PACKET interface test passed")
		})

		It("should create memif interface", func() {
			testutils.LogSection("Testing memif interface creation")
			vpp := vppFixture.Instance.GetVppLink()

			// Create memif socket directory in the VPP container
			testutils.LogStep("Creating memif socket directory (/run/vpp)")
			_, err := vppFixture.Instance.Exec("mkdir", "-p", "/run/vpp")
			Expect(err).ToNot(HaveOccurred(), "failed to create memif socket directory")

			// Register a memif socket filename
			testutils.LogStep("Registering memif socket filename in VPP")
			socketID, err := vpp.AddMemifSocketFileName("/run/vpp/memif-test.sock")
			Expect(err).ToNot(HaveOccurred(), "failed to add memif socket filename")
			testutils.LogSuccess("Memif socket registered (socketID: %d)", socketID)

			// Create memif interface
			testutils.LogStep("Creating memif interface (master, ethernet mode)")
			memif := &types.Memif{
				Role:        types.MemifMaster,
				Mode:        types.MemifModeEthernet,
				SocketID:    socketID,
				QueueSize:   1024,
				NumRxQueues: 1,
				NumTxQueues: 1,
			}

			err = vpp.CreateMemif(memif)
			Expect(err).ToNot(HaveOccurred(), "failed to create memif interface")
			Expect(memif.SwIfIndex).ToNot(BeZero(), "invalid memif interface index")
			testutils.LogSuccess("Memif interface created (swIfIndex: %d)", memif.SwIfIndex)

			// Verify memif interface
			testutils.LogStep("Verifying memif interface exists")
			assertions := testutils.NewVppAssertions(vpp)
			assertions.AssertMemifInterfaceExists(memif.SwIfIndex)
			testutils.LogSuccess("Memif interface test passed")
		})
	})
})
