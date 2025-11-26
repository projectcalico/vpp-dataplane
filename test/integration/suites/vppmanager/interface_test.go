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

package vppmanager_test

import (
	"fmt"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/vpp-dataplane/v3/test/integration/framework"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	VppImageEnv           = "VPP_IMAGE"
	VppBinaryEnv          = "VPP_BINARY"
	VppContainerExtraArgs = "VPP_CONTAINER_EXTRA_ARGS"
)

var (
	testCtx   *framework.TestContext
	vppImage  string
	vppBinary string
)

func TestVppManagerIntegration(t *testing.T) {
	// Skip if not running integration tests
	_, isIntegrationTest := os.LookupEnv(VppImageEnv)
	if !isIntegrationTest {
		t.Skip("Skipping vpp-manager integration tests (set VPP_IMAGE env variable to run)")
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "VPP Manager Integration Test Suite")
}

var _ = BeforeSuite(func() {
	var ok bool
	vppImage, ok = os.LookupEnv(VppImageEnv)
	Expect(ok).To(BeTrue(), fmt.Sprintf("Please set %s environment variable", VppImageEnv))
	Expect(vppImage).ToNot(BeEmpty(), fmt.Sprintf("Please set %s environment variable", VppImageEnv))

	vppBinary, ok = os.LookupEnv(VppBinaryEnv)
	Expect(ok).To(BeTrue(), fmt.Sprintf("Please set %s environment variable", VppBinaryEnv))
	Expect(vppBinary).ToNot(BeEmpty(), fmt.Sprintf("Please set %s environment variable", VppBinaryEnv))

	testCtx = framework.NewTestContext()
})

var _ = AfterSuite(func() {
	if testCtx != nil {
		testCtx.Cleanup()
	}
})

var _ = Describe("vpp-manager", func() {
	var vppFixture *framework.VppFixture

	BeforeEach(func() {
		vppFixture = &framework.VppFixture{
			Config: framework.DefaultVppConfig(),
		}
		vppFixture.Setup("test-vpp", vppImage, vppBinary, testCtx.Log)
	})

	AfterEach(func() {
		if vppFixture != nil {
			vppFixture.Teardown()
		}
	})

	Context("Interface", func() {
		It("TapInterface", func() {
			GinkgoWriter.Println("\n=== Testing TAP uplink interface configuration ===")
			GinkgoWriter.Println("  → Preparing dual-stack TAP uplink configuration")
			uplinkConfig := &framework.UplinkConfig{
				InterfaceName: "test-uplink",
				IPv4Address:   "192.168.1.10/24",
				IPv6Address:   "fd00::10/64",
				IPv4Gateway:   "192.168.1.1/24",
				IPv6Gateway:   "fd00::1/64",
				MTU:           1500,
			}

			GinkgoWriter.Println("  → Creating and configuring TAP interface")
			swIfIndex, err := vppFixture.Instance.ConfigureUplink(uplinkConfig)
			Expect(err).ToNot(HaveOccurred(), "failed to configure uplink")
			Expect(swIfIndex).ToNot(BeZero(), "invalid uplink interface index")
			GinkgoWriter.Printf("  ✓ TAP interface created (swIfIndex: %d)\n", swIfIndex)

			vpp := vppFixture.Instance.GetVppLink()
			assertions := framework.NewVppAssertions(vpp)

			// Verify interface is up
			GinkgoWriter.Println("  → Verifying interface state")
			assertions.AssertInterfaceIsUp(swIfIndex)
			GinkgoWriter.Println("    ✓ Interface is administratively up")

			// Verify IP addresses
			GinkgoWriter.Println("  → Verifying IP address configuration")
			assertions.AssertInterfaceHasIPAddress(swIfIndex, "192.168.1.10")
			GinkgoWriter.Println("    ✓ IPv4 address 192.168.1.10/24 configured")
			assertions.AssertInterfaceHasIPAddress(swIfIndex, "fd00::10")
			GinkgoWriter.Println("    ✓ IPv6 address fd00::10/64 configured")

			// Verify host side is configured
			GinkgoWriter.Println("  → Verifying host-side TAP configuration")
			output, err := vppFixture.Instance.Exec("ip", "addr", "show", "dev", uplinkConfig.InterfaceName)
			Expect(err).ToNot(HaveOccurred(), "failed to check host interface")
			Expect(string(output)).To(ContainSubstring("192.168.1.1"), "host interface missing IPv4")
			GinkgoWriter.Println("    ✓ Host IPv4 gateway 192.168.1.1 configured")
			Expect(string(output)).To(ContainSubstring("fd00::1"), "host interface missing IPv6")
			GinkgoWriter.Println("    ✓ Host IPv6 gateway fd00::1 configured")
			GinkgoWriter.Println("  ✓ TAP uplink test completed successfully")
		})

		It("AFPACKETInterface", func() {
			GinkgoWriter.Println("\n=== Testing AF_PACKET interface driver ===")
			vpp := vppFixture.Instance.GetVppLink()

			// Create a veth pair first
			GinkgoWriter.Println("  → Creating veth pair (veth0 <-> veth1) on host")
			_, err := vppFixture.Instance.Exec("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
			Expect(err).ToNot(HaveOccurred(), "failed to create veth pair")

			GinkgoWriter.Println("  → Bringing veth0 up on host")
			_, err = vppFixture.Instance.Exec("ip", "link", "set", "veth0", "up")
			Expect(err).ToNot(HaveOccurred(), "failed to bring up veth0")
			GinkgoWriter.Println("  ✓ Host veth pair created and configured")

			// Create AF_PACKET interface in VPP
			GinkgoWriter.Println("  → Creating AF_PACKET interface in VPP for veth0")
			swIfIndex, err := vpp.CreateAfPacket(&types.AfPacketInterface{
				GenericVppInterface: types.GenericVppInterface{
					HostInterfaceName: "veth0",
				},
			})
			Expect(err).ToNot(HaveOccurred(), "failed to create AF_PACKET interface")
			Expect(swIfIndex).ToNot(BeZero(), "invalid AF_PACKET interface index")
			GinkgoWriter.Printf("  ✓ AF_PACKET interface created (swIfIndex: %d)\n", swIfIndex)

			// Bring interface up
			GinkgoWriter.Println("  → Bringing AF_PACKET interface up in VPP")
			err = vpp.InterfaceAdminUp(swIfIndex)
			Expect(err).ToNot(HaveOccurred(), "failed to bring interface up")

			// Verify interface exists and is up
			GinkgoWriter.Println("  → Verifying interface is up")
			assertions := framework.NewVppAssertions(vpp)
			assertions.AssertInterfaceIsUp(swIfIndex)
			GinkgoWriter.Println("  ✓ AF_PACKET interface test completed successfully")
		})

		It("memifInterface", func() {
			GinkgoWriter.Println("\n=== Testing memif interface driver ===")
			vpp := vppFixture.Instance.GetVppLink()

			// Create memif socket directory in the VPP container
			GinkgoWriter.Println("  → Creating memif socket directory (/run/vpp)")
			_, err := vppFixture.Instance.Exec("mkdir", "-p", "/run/vpp")
			Expect(err).ToNot(HaveOccurred(), "failed to create memif socket directory")

			// Register a memif socket filename first
			GinkgoWriter.Println("  → Registering memif socket filename in VPP")
			socketID, err := vpp.AddMemifSocketFileName("/run/vpp/memif-test.sock")
			Expect(err).ToNot(HaveOccurred(), "failed to add memif socket filename")
			GinkgoWriter.Printf("  ✓ Memif socket registered (socketID: %d)\n", socketID)

			// Create memif socket and interface
			GinkgoWriter.Println("  → Creating memif interface (master, ethernet mode)")
			GinkgoWriter.Println("    - Queue size: 1024")
			GinkgoWriter.Println("    - RX queues: 1")
			GinkgoWriter.Println("    - TX queues: 1")
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
			GinkgoWriter.Printf("  ✓ Memif interface created (swIfIndex: %d)\n", memif.SwIfIndex)

			// Verify memif interface
			GinkgoWriter.Println("  → Verifying memif interface exists")
			assertions := framework.NewVppAssertions(vpp)
			assertions.AssertMemifInterfaceExists(memif.SwIfIndex)
			GinkgoWriter.Println("  ✓ Memif interface test completed successfully")
		})
	})

	Context("VPPConfig", func() {
		It("VPPConfig", func() {
			GinkgoWriter.Println("\n=== Testing VPP buffer and plugin configuration ===")
			vpp := vppFixture.Instance.GetVppLink()

			// Check buffer configuration via CLI
			GinkgoWriter.Println("  → Checking VPP buffer allocation via CLI")
			bufferOutput, err := vpp.RunCli("show buffers")
			Expect(err).ToNot(HaveOccurred(), "failed to get buffer info")
			Expect(bufferOutput).ToNot(BeEmpty(), "empty buffer output")

			// Verify buffers are allocated (check for "Avail" column in output)
			GinkgoWriter.Println("  → Verifying buffers are allocated")
			Expect(bufferOutput).To(MatchRegexp("(?i)avail"), "no available buffers")
			GinkgoWriter.Println("  ✓ VPP buffers allocated correctly")

			// Check plugin configuration
			GinkgoWriter.Println("  → Checking loaded VPP plugins")
			pluginOutput, err := vpp.RunCli("show plugins")
			Expect(err).ToNot(HaveOccurred(), "failed to get plugin info")

			GinkgoWriter.Println("  → Verifying dispatch_trace_plugin is loaded")
			Expect(pluginOutput).To(ContainSubstring("dispatch_trace_plugin.so"), "dispatch_trace_plugin plugin not loaded")
			GinkgoWriter.Println("    ✓ dispatch_trace_plugin.so loaded")

			// Check that DPDK plugin is disabled
			GinkgoWriter.Println("  → Verifying dpdk_plugin is disabled")
			Expect(pluginOutput).ToNot(ContainSubstring("dpdk_plugin.so"), "dpdk plugin should be disabled")
			GinkgoWriter.Println("    ✓ dpdk_plugin.so disabled")

			GinkgoWriter.Println("  ✓ VPP configuration test completed successfully")
		})
	})
})
