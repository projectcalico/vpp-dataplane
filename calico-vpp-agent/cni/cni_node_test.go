// Copyright (c) 2022 Cisco and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cni_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gs "github.com/onsi/gomega/gstruct"
	gobgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/config"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	agentConf "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/tests/mocks"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/tests/mocks/calico"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Names of integration tests arguments
const (
	IntegrationTestEnableArgName = "INTEGRATION_TEST"
	VppImageArgName              = "VPP_IMAGE"
	VppBinaryArgName             = "VPP_BINARY"
)

var (
	// vppImage is the name of docker image containing VPP binary
	vppImage string
	// vppBinary is the full path to VPP binary inside docker image
	vppBinary string
)

// TestCniIntegration runs all the ginkgo integration test inside CNI package
func TestCniIntegration(t *testing.T) {
	// skip test if test run is not integration test run (prevent accidental run of integration tests using go test ./...)
	_, isIntegrationTestRun := os.LookupEnv(IntegrationTestEnableArgName)
	if !isIntegrationTestRun {
		t.Skip("skipping CNI integration tests (set INTEGRATION_TEST env variable to run these tests)")
	}

	// integrate gomega and ginkgo -> register all CNI integration tests
	RegisterFailHandler(Fail)
	RunSpecs(t, "CNI Integration Suite")
}

var _ = BeforeSuite(func() {
	// extract common input for CNI integration tests
	var found bool
	vppImage, found = os.LookupEnv(VppImageArgName)
	if !found {
		Expect(vppImage).ToNot(BeEmpty(), fmt.Sprintf("Please specify docker image containing "+
			"VPP binary using %s environment variable.", VppImageArgName))
	}
	vppBinary, found = os.LookupEnv(VppBinaryArgName)
	if !found {
		Expect(vppBinary).ToNot(BeEmpty(), fmt.Sprintf("Please specify VPP binary (full path) "+
			"inside docker image %s using %s environment variable.", vppImage, VppBinaryArgName))
	}
})

// Common setup constants
const (
	UplinkIfName  = "uplink"
	UplinkIP      = "10.0.100.1"
	UplinkIPv6    = "A::1:1"
	GatewayIP     = "10.0.100.254"
	GatewayIPv6   = "A::1:254"
	ThisNodeIP    = UplinkIP
	ThisNodeIPv6  = UplinkIPv6
	AddedNodeIP   = "10.0.200.1"
	AddedNodeIPv6 = "A::2:1"
)

// VPPContainerName is name of container with VPP binary
const VPPContainerName = "cni-tests-vpp"

var _ = Describe("Node-related functionality of CNI", func() {
	var (
		log                *logrus.Logger
		vpp                *vpplink.VppLink
		connectivityServer *connectivity.ConnectivityServer
		client             *calico.CalicoClientStub
		ipamStub           *mocks.IpamCacheStub
		pubSubHandlerMock  *mocks.PubSubHandlerMock
		uplinkSwIfIndex    uint32
	)
	BeforeEach(func() {
		log = logrus.New()
		client = calico.NewCalicoClientStub()
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
	})

	JustBeforeEach(func() {
		startVPP()
		vpp, uplinkSwIfIndex = configureVPP(log)

		// setup connectivity server (functionality target of tests)
		if ipamStub == nil {
			ipamStub = mocks.NewIpamCacheStub()
		}
		connectivityServer = connectivity.NewConnectivityServer(vpp, ipamStub, client,
			log.WithFields(logrus.Fields{"subcomponent": "connectivity"}))
		connectivityServer.SetOurBGPSpec(&oldv3.NodeBGPSpec{})
		connectivityServer.SetFelixConfig(&config.Config{})
	})

	Describe("Addition of the node", func() {
		Context("With FLAT connectivity", func() {
			It("should only configure correct routes in VPP", func() {
				By("Adding node")
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet(AddedNodeIP + "/24"),
					NextHop:          net.ParseIP(GatewayIP),
					ResolvedProvider: connectivity.FLAT,
					Custom:           nil,
				}, false)

				By("Getting routes and check them")
				routes, err := vpp.GetRoutes(0, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP")
				Expect(routes).To(ContainElements(
					// route to destination going via gateway
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet("10.0.200.0/24"))),
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"Gw": Equal(net.ParseIP(GatewayIP).To4()),
						})),
					}),
					// using gateway means using our uplink interface
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(GatewayIP + "/32"))),
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(uplinkSwIfIndex),
						})),
					}),
				), "Can't find 2 routes that should steer the traffic to newly added node")
			})
		})
		Context("With IPSEC connectivity", func() {
			BeforeEach(func() {
				// add node pool for IPSec (uses IPIP tunnels)
				ipamStub = mocks.NewIpamCacheStub()
				ipamStub.AddPrefixIPPool(ipNet(AddedNodeIP+"/24"), &apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("custom-test-pool-for-ipsec-%s", AddedNodeIP+"/24"),
					},
					Spec: apiv3.IPPoolSpec{
						CIDR: AddedNodeIP + "/24",
						// important for connectivity provider selection (IPSec uses IPIP tunnel)
						IPIPMode: apiv3.IPIPModeAlways,
					},
				})

				// Enables IPSec (=uses IPSec over IPIP tunnel and not pure IPIP tunnel)
				agentConf.EnableIPSec = true

				// setup PubSub handler to catch TunnelAdded events
				pubSubHandlerMock = mocks.NewPubSubHandlerMock(common.TunnelAdded)
				pubSubHandlerMock.Start()

				// setting Ikev2 PreShared Key to non-empty string as VPP fails with empty string
				// (empty preshared key = no IPSec security => makes no sense => VPP gives configuration error)
				agentConf.IPSecIkev2Psk = "testing-preshared-key-for-IPSec"
			})

			// TODO test IPSec tunnel delete
			// TODO test IPSec tunnel sharing for multiple connections
			// TODO test multiple IPSec tunnels (there is created a group of IPSec at once)

			// FIXME This is partial test due to not simulating second IPSec node where the IPSec tunnel should end.
			//  The IPSec implementation in VPP can't negotiate with the other IPSec tunnel end node anything, so
			//  i guess that VPP is not showing a lot of stuff that it should be there after up and running
			//  IPSec tunnel between 2 nodes.
			//  => not testing rest of IPSec settings, IPSec's IPIP tunnel to be in UP state, test existence of
			//  route to each IPSec tunnel (1 multipath route)
			It("should have setup IPIP tunnel as backend and all IPSec settings (only PARTIAL test!)", func() {
				//Note: not testing setting of IPsecAsyncMode and threads dedicated to IPSec (CryptoWorkers)
				// inside RescanState() function call
				By("Adding node")
				configureBGPNodeIPAddresses(connectivityServer)
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet(AddedNodeIP + "/24"), // FIXME destination and nodeIP are probably separate things!
					NextHop:          net.ParseIP(AddedNodeIP),    // next hop == other node IP (for IPSec impl)
					ResolvedProvider: connectivity.IPSEC,
					Custom:           nil,
				}, false)

				By("Checking IP-IP tunnel")
				tunnels, err := vpp.ListIPIPTunnels()
				Expect(err).ToNot(HaveOccurred(),
					"Failed to get IP-IP tunnels from VPP (for IPSec checking)")
				// Note: this is guessing based on existing interfaces in VPP, could be done better by listing
				// interfaces from VPP and filtering the correct one FIXME do it better?
				ipipSwIfIndex := uplinkSwIfIndex + 1
				backendIPIPTunnel := &types.IPIPTunnel{
					Src:       net.ParseIP(ThisNodeIP).To4(),
					Dst:       net.ParseIP(AddedNodeIP).To4(),
					TableID:   0, // not filled -> used default VRF table
					SwIfIndex: ipipSwIfIndex,
				}
				Expect(tunnels).To(ContainElements(backendIPIPTunnel))

				By("checking pushing of TunnelAdded event")
				// Note: VPP configuration done by receiver of this event is out of scope for this test
				Expect(pubSubHandlerMock.ReceivedEvents).To(ContainElement(common.CalicoVppEvent{
					Type: common.TunnelAdded,
					New:  ipipSwIfIndex, // IPSec tunnel uses IPIP tunnel
				}))

				By("checking IPSec's IPIP tunnel interface attributes (Unnumbered)")
				unnumberedDetails, err := vpp.InterfaceGetUnnumbered(ipipSwIfIndex)
				Expect(err).ToNot(HaveOccurred(),
					"can't get unnumbered details of IPSec's IPIP tunnel interface")
				Expect(unnumberedDetails.IPSwIfIndex).To(Equal(
					interface_types.InterfaceIndex(agentConf.DataInterfaceSwIfIndex)),
					"Unnumberred IPSec's IPIP tunnel interface doesn't "+
						"get IP address from expected interface")

				By("checking IPSec's IPIP tunnel interface attributes (GSO+CNAT)")
				// Note: no specialized binary api or VPP CLI for getting GSO on IPIP tunnel interface -> using
				// Feature Arcs (https://wiki.fd.io/view/VPP/Feature_Arcs) to detect it (GSO is using them to steer
				// traffic), Feature Arcs have no binary API -> using VPP's VPE binary API
				featuresStr, err := vpp.RunCli(fmt.Sprintf("sh interface %d features", ipipSwIfIndex))
				Expect(err).ToNot(HaveOccurred(),
					"failed to get IPSec's IPIP tunnel interface's configured features")
				featuresStr = strings.ToLower(featuresStr)
				var GSOFeatureArcs = []string{"gso-ip4", "gso-ip6", "gso-l2-ip4", "gso-l2-ip6"}
				for _, gsoStr := range GSOFeatureArcs {
					// Note: not checking full Feature Arc (i.e. ipv4-unicast: gso-ipv4), just the destination
					// of traffic steering. This is enough because without GSO enabled, the destination would not exist.
					Expect(featuresStr).To(ContainSubstring(gsoStr), fmt.Sprintf("GSO not fully enabled "+
						"due to missing %s in configured features arcs %s", gsoStr, featuresStr))
				}
				var CNATFeatureArcs = []string{"cnat-input-ip4", "cnat-input-ip6", "cnat-output-ip4", "cnat-output-ip6"}
				for _, cnatStr := range CNATFeatureArcs {
					// Note: could be enhanced by checking the full Feature Arc (from where we steer traffic to cnat)
					Expect(featuresStr).To(ContainSubstring(cnatStr), fmt.Sprintf("CNAT not fully enabled "+
						"due to missing %s in configured features arcs %s", cnatStr, featuresStr))
				}

				By("checking route for IPSec's IPIP tunnel from pod VRF")
				routes, err := vpp.GetRoutes(common.PodVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for Pod VRF")
				Expect(routes).To(ContainElements(
					// when IPIP is created it makes steering route with for NextHop/<max CIRD mask length> from Pod VRF
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(AddedNodeIP + "/32"))),
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(ipipSwIfIndex),
						})),
					})))

				By("checking IKEv2 profile")
				profiles, err := vpp.ListIKEv2Profiles()
				Expect(err).ToNot(HaveOccurred(), "Failed to get IKEv2 profiles from VPP")
				Expect(profiles).To(ContainElements(
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Name":   Equal(connectivity.NewIpsecTunnel(backendIPIPTunnel).Profile()),
						"TunItf": Equal(ipipSwIfIndex),
						"Auth": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"Data": Equal([]byte(agentConf.IPSecIkev2Psk)),
						}),
						//permissive (local/remote) traffic selectors
						"LocTs": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"ProtocolID": Equal(uint8(0)),
							"StartPort":  Equal(uint16(0)),
							"EndPort":    Equal(uint16(0xffff)),
							"StartAddr":  Equal(types.ToVppAddress(net.ParseIP("0.0.0.0"))),
							"EndAddr":    Equal(types.ToVppAddress(net.ParseIP("255.255.255.255"))),
						}),
						"RemTs": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"ProtocolID": Equal(uint8(0)),
							"StartPort":  Equal(uint16(0)),
							"EndPort":    Equal(uint16(0xffff)),
							"StartAddr":  Equal(types.ToVppAddress(net.ParseIP("0.0.0.0"))),
							"EndAddr":    Equal(types.ToVppAddress(net.ParseIP("255.255.255.255"))),
						}),
					}),
				))

				// Note: strangely the IKEv2 profile didn't have filled the tunnel source and destination IP addresses
				// even when clearly visible in the VPP CLI -> using VPP CLI (Is this another problem when there
				// is no second IPSec node where the IPSec tunnel can end and therefore no IPSec negotiation can occur?)
				profileStr, err := vpp.RunCli("show ikev2 profile")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get IPSec's IKEv2 profile configuration from VPP CLI")
				Expect(profileStr).To(ContainSubstring(ThisNodeIP),
					"IKEv2 profile doesn't contain IPSec tunnel source IP address")
				Expect(profileStr).To(ContainSubstring(AddedNodeIP),
					"IKEv2 profile doesn't contain IPSec tunnel destination IP address")
			})

			AfterEach(func() {
				if pubSubHandlerMock != nil {
					Expect(pubSubHandlerMock.Stop()).ToNot(HaveOccurred(),
						"can't properly stop mock of PubSub's handler")
				}
				agentConf.EnableIPSec = false // disable for following tests
			})
		})
		Context("With VXLAN connectivity", func() {
			BeforeEach(func() {
				// add node pool for VXLAN
				ipamStub = mocks.NewIpamCacheStub()
				ipamStub.AddPrefixIPPool(ipNet(AddedNodeIP+"/24"), &apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("custom-test-pool-for-vxlan-%s", AddedNodeIP+"/24"),
					},
					Spec: apiv3.IPPoolSpec{
						CIDR:      AddedNodeIP + "/24",
						VXLANMode: apiv3.VXLANModeAlways, // important for connectivity provider selection
					},
				})

				// setup PubSub handler to catch TunnelAdded events
				pubSubHandlerMock = mocks.NewPubSubHandlerMock(common.TunnelAdded)
				pubSubHandlerMock.Start()
			})

			// TODO test removal of VXLAN tunnel
			// TODO test cases when some VXLAN tunnels already exists before CNI calls (VXLAN tunnel reuse,
			//  VXLAN tunnel is removed only when last prefix connectivity that is using given VXLAN is removed)

			It("should have vxlan tunnel and route forwarding to it", func() {
				By("Initialize VXLAN and add static VXLAN configuration")
				err := connectivityServer.ForceRescanState(connectivity.VXLAN)
				Expect(err).ToNot(HaveOccurred(), "can't rescan state of VPP and therefore "+
					"can't properly create ???")

				By("Checking VPP's node graph modifications for VXLAN")
				ipv4DecapNextIndex := assertNextNodeLink("vxlan4-input", "ip4-input", vpp)
				assertNextNodeLink("vxlan6-input", "ip6-input", vpp)

				By("Adding node")
				configureBGPNodeIPAddresses(connectivityServer)
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet(AddedNodeIP + "/24"), // FIXME destination and nodeIP are probably separate things!
					NextHop:          net.ParseIP(GatewayIP),
					ResolvedProvider: connectivity.VXLAN,
					Custom:           nil,
				}, false)

				By("Checking VXLAN tunnel")
				tunnels, err := vpp.ListVXLanTunnels()
				Expect(err).ToNot(HaveOccurred(), "Failed to get VXLAN tunnels from VPP")
				// Note: this is guessing based on existing interfaces in VPP, could be done better by listing
				// interfaces from VPP and filtering the correct one FIXME do it better?
				vxlanSwIfIndex := uplinkSwIfIndex + 1
				Expect(tunnels).To(ContainElements(types.VXLanTunnel{
					SrcAddress:     net.ParseIP(ThisNodeIP).To4(), // set by configureBGPNodeIPAddresses() call
					DstAddress:     net.ParseIP(GatewayIP).To4(),
					SrcPort:        agentConf.DefaultVXLANPort,
					DstPort:        agentConf.DefaultVXLANPort,
					Vni:            agentConf.DefaultVXLANVni,
					DecapNextIndex: uint32(ipv4DecapNextIndex),
					SwIfIndex:      vxlanSwIfIndex,
				}))

				By("checking VXLAN tunnel interface attributes (Unnumbered)")
				unnumberedDetails, err := vpp.InterfaceGetUnnumbered(vxlanSwIfIndex)
				Expect(err).ToNot(HaveOccurred(),
					"can't get unnumbered details of VXLAN tunnel interface")
				Expect(unnumberedDetails.IPSwIfIndex).To(Equal(
					interface_types.InterfaceIndex(agentConf.DataInterfaceSwIfIndex)),
					"Unnumberred VXLAN tunnel interface doesn't get IP address from expected interface")

				By("checking VXLAN tunnel interface attributes (GSO+CNAT)")
				// Note: no specialized binary api or VPP CLI for getting GSO on VXLAN tunnel interface -> using
				// Feature Arcs (https://wiki.fd.io/view/VPP/Feature_Arcs) to detect it (GSO is using them to steer
				// traffic), Feature Arcs have no binary API -> using VPP's VPE binary API
				featuresStr, err := vpp.RunCli(fmt.Sprintf("sh interface %d features", vxlanSwIfIndex))
				Expect(err).ToNot(HaveOccurred(),
					"failed to get VXLAN tunnel interface's configured features")
				featuresStr = strings.ToLower(featuresStr)
				var GSOFeatureArcs = []string{"gso-ip4", "gso-ip6", "gso-l2-ip4", "gso-l2-ip6"}
				for _, gsoStr := range GSOFeatureArcs {
					// Note: not checking full Feature Arc (i.e. ipv4-unicast: gso-ipv4), just the destination
					// of traffic steering. This is enough because without GSO enabled, the destination would not exist.
					Expect(featuresStr).To(ContainSubstring(gsoStr), fmt.Sprintf("GSO not fully enabled "+
						"due to missing %s in configured features arcs %s", gsoStr, featuresStr))
				}
				var CNATFeatureArcs = []string{"cnat-input-ip4", "cnat-input-ip6", "cnat-output-ip4", "cnat-output-ip6"}
				for _, cnatStr := range CNATFeatureArcs {
					// Note: could be enhanced by checking the full Feature Arc (from where we steer traffic to cnat)
					Expect(featuresStr).To(ContainSubstring(cnatStr), fmt.Sprintf("CNAT not fully enabled "+
						"due to missing %s in configured features arcs %s", cnatStr, featuresStr))
				}

				By("checking VXLAN tunnel interface attributes (Up state)")
				interfaceDetails, err := vpp.GetInterfaceDetails(vxlanSwIfIndex)
				Expect(err).ToNot(HaveOccurred(), "can't get VXLAN tunnel interface's basic attributes ")
				Expect(interfaceDetails.IsUp).To(BeTrue(), "VXLAN tunnel interface should be in UP state")

				By("checking 2 routes")
				routes, err := vpp.GetRoutes(common.PodVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for Pod VRF")
				Expect(routes).To(ContainElements(
					// when VXLAN is created it makes steering route with for NextHop/<max CIRD mask length> from Pod VRF
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(GatewayIP + "/32"))),
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(vxlanSwIfIndex),
						})),
					})))
				routes, err = vpp.GetRoutes(common.DefaultVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for default VRF")
				Expect(routes).To(ContainElements(
					// steering route for NodeConnectivity.Dst using vxlan that is leading to the added node
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(AddedNodeIP + "/24"))), // NodeConnectivity.Dst
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(vxlanSwIfIndex),
							"Gw":        Equal(net.ParseIP(ThisNodeIP).To4()), // TODO why this node IP when leaving node ?
						})),
					}),
				), "Can't find 2 routes that should steer the traffic to newly added node")

				By("checking pushing of TunnelAdded event")
				// Note: VPP configuration done by receiver of this event is out of scope for this test
				Expect(pubSubHandlerMock.ReceivedEvents).To(ContainElement(common.CalicoVppEvent{
					Type: common.TunnelAdded,
					New:  vxlanSwIfIndex,
				}))
			})

			AfterEach(func() {
				if pubSubHandlerMock != nil {
					Expect(pubSubHandlerMock.Stop()).ToNot(HaveOccurred(),
						"can't properly stop mock of PubSub's handler")
				}
			})
		})
		Context("With IP-IP connectivity", func() {
			BeforeEach(func() {
				// add node pool for IPIP
				ipamStub = mocks.NewIpamCacheStub()
				ipamStub.AddPrefixIPPool(ipNet(AddedNodeIP+"/24"), &apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("custom-test-pool-for-ipip-%s", AddedNodeIP+"/24"),
					},
					Spec: apiv3.IPPoolSpec{
						CIDR:     AddedNodeIP + "/24",
						IPIPMode: apiv3.IPIPModeAlways, // important for connectivity provider selection
					},
				})

				// setup PubSub handler to catch TunnelAdded events
				pubSubHandlerMock = mocks.NewPubSubHandlerMock(common.TunnelAdded)
				pubSubHandlerMock.Start()
			})

			// TODO test removal of IPIP tunnel
			// TODO test cases when some IPIP tunnels already exists before CNI calls (IPIP tunnel reuse,
			//  IPIP tunnel is removed only when last prefix connectivity that is using given IPIP is removed)

			It("should have IP-IP tunnel and route forwarding to it", func() {
				By("Adding node")
				configureBGPNodeIPAddresses(connectivityServer)
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet(AddedNodeIP + "/24"), // FIXME destination and nodeIP are probably separate things!
					NextHop:          net.ParseIP(GatewayIP),
					ResolvedProvider: connectivity.IPIP,
					Custom:           nil,
				}, false)

				By("Checking IP-IP tunnel")
				tunnels, err := vpp.ListIPIPTunnels()
				Expect(err).ToNot(HaveOccurred(), "Failed to get IP-IP tunnels from VPP")
				// Note: this is guessing based on existing interfaces in VPP, could be done better by listing
				// interfaces from VPP and filtering the correct one FIXME do it better?
				ipipSwIfIndex := uplinkSwIfIndex + 1
				Expect(tunnels).To(ContainElements(&types.IPIPTunnel{
					Src:       net.ParseIP(ThisNodeIP).To4(), // set by configureBGPNodeIPAddresses() call
					Dst:       net.ParseIP(GatewayIP).To4(),
					TableID:   0, // not filled -> used default VRF table
					SwIfIndex: ipipSwIfIndex,
				}))

				By("checking IPIP tunnel interface attributes (Unnumbered)")
				unnumberedDetails, err := vpp.InterfaceGetUnnumbered(ipipSwIfIndex)
				Expect(err).ToNot(HaveOccurred(),
					"can't get unnumbered details of IPIP tunnel interface")
				Expect(unnumberedDetails.IPSwIfIndex).To(Equal(
					interface_types.InterfaceIndex(agentConf.DataInterfaceSwIfIndex)),
					"Unnumberred IPIP tunnel interface doesn't get IP address from expected interface")

				By("checking IPIP tunnel interface attributes (GSO+CNAT)")
				// Note: no specialized binary api or VPP CLI for getting GSO on IPIP tunnel interface -> using
				// Feature Arcs (https://wiki.fd.io/view/VPP/Feature_Arcs) to detect it (GSO is using them to steer
				// traffic), Feature Arcs have no binary API -> using VPP's VPE binary API
				featuresStr, err := vpp.RunCli(fmt.Sprintf("sh interface %d features", ipipSwIfIndex))
				Expect(err).ToNot(HaveOccurred(),
					"failed to get IPIP tunnel interface's configured features")
				featuresStr = strings.ToLower(featuresStr)
				var GSOFeatureArcs = []string{"gso-ip4", "gso-ip6", "gso-l2-ip4", "gso-l2-ip6"}
				for _, gsoStr := range GSOFeatureArcs {
					// Note: not checking full Feature Arc (i.e. ipv4-unicast: gso-ipv4), just the destination
					// of traffic steering. This is enough because without GSO enabled, the destination would not exist.
					Expect(featuresStr).To(ContainSubstring(gsoStr), fmt.Sprintf("GSO not fully enabled "+
						"due to missing %s in configured features arcs %s", gsoStr, featuresStr))
				}
				var CNATFeatureArcs = []string{"cnat-input-ip4", "cnat-input-ip6", "cnat-output-ip4", "cnat-output-ip6"}
				for _, cnatStr := range CNATFeatureArcs {
					// Note: could be enhanced by checking the full Feature Arc (from where we steer traffic to cnat)
					Expect(featuresStr).To(ContainSubstring(cnatStr), fmt.Sprintf("CNAT not fully enabled "+
						"due to missing %s in configured features arcs %s", cnatStr, featuresStr))
				}

				By("checking IPIP tunnel interface attributes (Up state)")
				interfaceDetails, err := vpp.GetInterfaceDetails(ipipSwIfIndex)
				Expect(err).ToNot(HaveOccurred(), "can't get IPIP tunnel interface's basic attributes ")
				Expect(interfaceDetails.IsUp).To(BeTrue(), "IPIP tunnel interface should be in UP state")

				By("checking 2 routes")
				routes, err := vpp.GetRoutes(common.PodVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for Pod VRF")
				Expect(routes).To(ContainElements(
					// when IPIP is created it makes steering route with for NextHop/<max CIRD mask length> from Pod VRF
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(GatewayIP + "/32"))),
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(ipipSwIfIndex),
						})),
					})))
				routes, err = vpp.GetRoutes(common.DefaultVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for default VRF")
				Expect(routes).To(ContainElements(
					// steering route for NodeConnectivity.Dst using ipip that is leading to the added node
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(AddedNodeIP + "/24"))), // NodeConnectivity.Dst
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(ipipSwIfIndex),
						})),
					}),
				), "Can't find 2 routes that should steer the traffic to newly added node")

				By("checking pushing of TunnelAdded event")
				// Note: VPP configuration done by receiver of this event is out of scope for this test
				Expect(pubSubHandlerMock.ReceivedEvents).To(ContainElement(common.CalicoVppEvent{
					Type: common.TunnelAdded,
					New:  ipipSwIfIndex,
				}))
			})

			AfterEach(func() {
				if pubSubHandlerMock != nil {
					Expect(pubSubHandlerMock.Stop()).ToNot(HaveOccurred(),
						"can't properly stop mock of PubSub's handler")
				}
			})
		})
		Context("With Wireguard connectivity", func() {
			// TODO impl Wireguard test
		})
		Context("With SRv6 connectivity", func() {
			// Simple use cases of segment routing over IPv6 (SRv6) are used in VPP-dataplane. Therefor some
			// concepts might seem overcomplicated (please refer to https://datatracker.ietf.org/doc/html/rfc8986 for
			// full explanation of SRv6)
			// The segment routing cuts routing path of packet to multiple segments. At the start node the traffic
			// gets steered (Steering configuration) into segment routing policy (SRPolicy configuration). It
			// encapsulates packet with info which segments should packet visit. Each segment have configured
			// behaviour (Localsid configuration, LOCAL Segment ID=LOCALSID) what to do with packet. It can be
			// configured to go to next segment end(Localsid) or it can exit the tunnel(multiple ways how to do it)
			// In our case, we use only Localsids that exit tunnel by decapsulating the packet(remove SRv6
			// from packet header) and look for routing in local VPP FIB table. This means that we are using
			// always only one segment. However, the routing from one segment end to another is done as normal
			// IPv6 routing. This means that after steering and applying SR policy, some IPv6 routing still
			// must be configured.

			BeforeEach(func() {
				// configuring global config for SRv6 ConnectivityProvider
				agentConf.EnableSRv6 = true
				agentConf.SRv6localSidIPPool = "B::/16" // also B::<node number>/112 subnet for LocalSids for given node
				agentConf.SRv6policyIPPool = "C::/16"   // also C::<node number>/112 subnet for BindingSIDs(=BSID=PolicyIP) for given node
				agentConf.NodeName = "node1"

				// add node pool for SRv6 (subnet of agentConf.SRv6localSidIPPool)
				addIPPoolForCalicoClient(client, fmt.Sprintf("sr-localsids-pool-%s", agentConf.NodeName), "B::1:0/112")

				// SID/BSID format for testing: <BSID/Localsid prefix><node id>:<suffix created by IPAM IP assignment>
				// i.e. "C::2:1" = First IP generated by IPAM on node 2 and it should be used as policy BSID
			})
			Context("When the SRv6 tunnels end in this node", func() {
				It("must have configured the tunnel endpoint(Localsid)", func() {
					By("Enforce rescan with VPP that is used in SRv6 connectivity provider " +
						"for tunnel endpoint(localsid) creation")
					// Note: localsids as tunnel endpoints are not bound to any particular tunnel, they can
					// exists without tunnel or server one or more tunnels at the same time
					// -> they are not dependent on anything from NodeConnection event and are created before event loop
					err := connectivityServer.ForceRescanState(connectivity.SRv6)
					Expect(err).ToNot(HaveOccurred(), "can't rescan state of VPP and therefore "+
						"can't properly create SRv6 tunnel endpoints(LocalSids) for this node")

					By("Verify tunnel endpoint(localsid) presence")
					localsids, err := vpp.ListSRv6Localsid()
					Expect(err).ToNot(HaveOccurred(), "can't get localsids")
					Expect(localsids).To(ContainElement(gs.PointTo(
						gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							// first IPAM-assigned IP for SRv6 node pool
							"Localsid": Equal(iptypesIP6Address("B::1:1")),
							// exit tunnel by decapsulation + further routing using IPv4 routing table
							// (had to be Ipv4 traffic before encapsulation)
							"Behavior": Equal(types.SrBehaviorDT4),
							// IPv4 table used for further routing of decapsulate traffic (Id is per IP address family)
							"FibTable": Equal(uint32(0)),
						}),
					)), "Can't find the tunnel endpoint for IPv4 traffic")
					Expect(localsids).To(ContainElement(gs.PointTo(
						gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							// second IPAM-assigned IP for SRv6 node pool
							"Localsid": Equal(iptypesIP6Address("B::1:2")),
							// exit tunnel by decapsulation + further routing using IPv6 routing table
							// (had to be Ipv6 traffic before encapsulation)
							"Behavior": Equal(types.SrBehaviorDT6),
							// IPv6 table used for further routing of decapsulate traffic (Id is per IP address family)
							"FibTable": Equal(uint32(0)),
						}),
					)), "Can't find the tunnel endpoint for IPv6 traffic")
				})
			})
			Context("When the SRv6 tunnel starts in this node", func() {
				It("must have configured traffic steering into SRv6 policy for tunnel encapsulation and "+
					"encapsulated traffic forwarding", func() {
					// variables related to tunnel-end node (node id=2)
					_, tunnelEndNodeIPNet, _ := net.ParseCIDR(AddedNodeIP + "/24")
					policyBsid := net.ParseIP("C::2:1")      // normally generated by IPAM on tunnel end node
					tunnelEndLocalSid := ipNet("B::2:1/128") // normally generated by IPAM on tunnel end node

					By("Setting and checking encapsulation source for SRv6")
					// Note: encapsulation source sets source IP for traffic when exiting tunnel(=decapsulating)
					configureBGPNodeIPAddresses(connectivityServer)
					err := connectivityServer.ForceRescanState(connectivity.SRv6)
					Expect(err).ToNot(HaveOccurred(), "can't rescan state of VPP and therefore "+
						"can't properly set encapsulation source IP for this node")
					// Note: no specialized binary api for getting SR encap source address -> using VPP's VPE binary API
					encapStr, err := vpp.RunCli("show sr encaps source addr")
					Expect(err).ToNot(HaveOccurred(), "failed to get SR encapsulation source address")
					Expect(strings.ToLower(encapStr)).To(ContainSubstring(strings.ToLower(UplinkIPv6)),
						"sr encapsulation source address is misconfigured")

					By("Adding node (the tunnel end node IP destination)")
					err = connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
						Dst:              *tunnelEndNodeIPNet,
						NextHop:          net.ParseIP(AddedNodeIPv6), // TODO check if this is right? next hop is not the other side of outgoing interface, but IPv6 of added node?
						ResolvedProvider: connectivity.SRv6,
						Custom:           nil,
					}, false)
					Expect(err).ToNot(HaveOccurred(), "Failed to make the initial part of "+
						"configuration of SRv6 tunnel")

					By("Adding SRv6 tunnel (retrieved by BGP watcher from tunnel-end node)")
					// The tunnel-end node watches localsids on its node. On new localsid detection it creates
					// policy/tunnel info(1 segment long SRv6 tunnel) leading to that new localsid (to tunnel-end
					// node). Then it uses BGP to inform this node (the tunnel start node) about it. The BGP watcher
					// catches it and sends event to connectivity server on this node and that results in call below.
					err = connectivityServer.UpdateSRv6Policy(&common.NodeConnectivity{
						Dst:              net.IPNet{},
						NextHop:          net.ParseIP(AddedNodeIPv6),
						ResolvedProvider: "",
						Custom: &common.SRv6Tunnel{ // see bgp_watcher.go: Server.getSRPolicy(...)
							Dst:      net.ParseIP(AddedNodeIPv6),
							Bsid:     policyBsid, // the same as Policy.BSID
							Sid:      nil,        // not used
							Behavior: uint8(gobgpapi.SRv6Behavior_END_DT4),
							Priority: 123,
							Policy: &types.SrPolicy{
								Bsid:     types.ToVppIP6Address(policyBsid),
								IsSpray:  false, // hardcoded usage
								IsEncap:  true,  // hardcoded usage
								FibTable: 0,     // hardcoded usage
								SidLists: []types.Srv6SidList{{
									NumSids: uint8(1),
									Weight:  1,
									Sids:    sidArray(types.ToVppIP6Address(tunnelEndLocalSid.IP)),
								}},
							},
						},
					}, false)
					Expect(err).ToNot(HaveOccurred(), "Failed to finish the SRv6 tunnel "+
						"configuration (steering and policy)")

					By("Adding Srv6 traffic routing")
					// TODO check from where this is called in full K8s/Calico/VPP installation and whether
					//  we call it with correct input values here
					err = connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
						Dst:              *tunnelEndLocalSid,
						NextHop:          net.ParseIP(GatewayIPv6),
						ResolvedProvider: connectivity.SRv6,
						Custom:           nil,
					}, false)
					Expect(err).ToNot(HaveOccurred(),
						"Failed to add configuration for SRv6 traffic routing")

					By("Checking steering of traffic")
					steerings, err := vpp.ListSRv6Steering()
					Expect(err).ToNot(HaveOccurred(), "can't get steering list from VPP")
					Expect(steerings).To(ConsistOf(&types.SrSteer{
						TrafficType: types.SR_STEER_IPV4,
						FibTable:    0,                                     // steering traffic from main FIB table by default
						Prefix:      types.ToVppPrefix(tunnelEndNodeIPNet), // L3 steering by prefix
						SwIfIndex:   0,                                     // not used as it is not steering of traffic from interface
						Bsid:        types.ToVppIP6Address(policyBsid),
					}), "Can't find SRv6 steering")

					By("Checking policy")
					policies, err := vpp.ListSRv6Policies()
					Expect(err).ToNot(HaveOccurred(), "can't get policies list from VPP")
					Expect(policies).To(ConsistOf(&types.SrPolicy{
						Bsid:     types.ToVppIP6Address(policyBsid),
						IsSpray:  false, // hardcoded usage
						IsEncap:  true,  // hardcoded usage
						FibTable: 0,     // hardcoded usage
						SidLists: []types.Srv6SidList{{
							NumSids: uint8(1),
							Weight:  1,
							Sids:    sidArray(types.ToVppIP6Address(tunnelEndLocalSid.IP)),
						}},
					}), "Can't find SRv6 policy")

					By("Checking forwarding of SRv6 tunnel traffic out of node")
					routes, err := vpp.GetRoutes(0, true)
					Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP")
					Expect(routes).To(ContainElements(
						// route to Localsid on the tunnel-end node (SRv6 encapsulated traffic forwarding)
						gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"Dst": gs.PointTo(Equal(*tunnelEndLocalSid)),
							"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
								"Gw":        Equal(net.ParseIP(GatewayIPv6)),
								"SwIfIndex": Equal(agentConf.DataInterfaceSwIfIndex),
							})),
						}),
					), "Can't find forwarding of SRv6 tunnel traffic out of node")
				})
			})
		})
	})

	AfterEach(func() {
		teardownVPP()
	})
})

func configureBGPNodeIPAddresses(connectivityServer *connectivity.ConnectivityServer) {
	connectivityServer.SetOurBGPSpec(&oldv3.NodeBGPSpec{
		IPv4Address: ThisNodeIP + "/24",
		IPv6Address: ThisNodeIPv6 + "/128",
	})
}

// assertNextNodeLink asserts that in VPP graph the given node has linked the linkedNextNode as one of its
// "next" nodes for processing. It returns to node specific index of the checked next node.
func assertNextNodeLink(node, linkedNextNode string, vpp *vpplink.VppLink) int {
	// get the node information from VPP (No VPP binary API for that -> using VPE)
	nodeInfoStr, err := vpp.RunCli(fmt.Sprintf("show node %s", node))
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("failed to VPP graph info for node %s", node))

	// asserting next node
	Expect(strings.ToLower(nodeInfoStr)).To(ContainSubstring(strings.ToLower(linkedNextNode)),
		fmt.Sprintf("can't find added next node %s in node %s information", linkedNextNode, node))

	// getting next node's index that is relative to the given node (this is kind of brittle as we parse VPP CLI output)
	linesToNextNode := strings.Split(strings.Split(nodeInfoStr, linkedNextNode)[0], "\n")
	indexStrOfLinkedNextNode := strings.TrimSpace(linesToNextNode[len(linesToNextNode)-1][:10])
	nextNodeIndex, err := strconv.Atoi(indexStrOfLinkedNextNode)
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("can't parse next node index "+
		"in given node from VPP CLI output %s", nodeInfoStr))

	return nextNodeIndex
}

// startVPP creates docker container and runs inside the VPP
func startVPP() {
	// prepare VPP configuration
	vppBinaryConfigArg := `unix {
			nodaemon
			full-coredump
			cli-listen /var/run/vpp/cli2.sock
			pidfile /run/vpp/vpp2.pid
		  }
		  api-trace { on }
		  cpu {
			  workers 0
		  }
		  socksvr {
			  socket-name /var/run/vpp/vpp-api-test.sock
		  }
		  plugins {
			  plugin default { enable }
			  plugin dpdk_plugin.so { disable }
			  plugin calico_plugin.so { enable }
			  plugin ping_plugin.so { disable }
		  }
		  buffers {
			buffers-per-numa 131072
		  }`

	// docker container cleanup (failed test that didn't properly clean up docker containers?)
	err := exec.Command("docker", "rm", "-f", VPPContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to clean up old VPP docker container")

	// start VPP inside docker container
	err = exec.Command("docker", "run", "-d", "--privileged", "--name", VPPContainerName,
		"-v", "/tmp/"+VPPContainerName+":/var/run/vpp/",
		"-v", "/proc:/proc", // needed for manipulation of another docker container's network namespace
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0", // enable IPv6 in container (to set IPv6 on host's end of uplink)
		"--entrypoint", vppBinary, vppImage,
		vppBinaryConfigArg).Run()
	Expect(err).Should(BeNil(), "Failed to start VPP inside docker container")

	time.Sleep(1 * time.Second) // TODO wait properly for socket to appear (<1s wait?)
	// fix file permissions for VPP binary socket exposed from docker container
	err = exec.Command("docker", "exec", VPPContainerName, "chmod", "o+rw",
		"/var/run/vpp/vpp-api-test.sock").Run()
	Expect(err).Should(BeNil(), "Failed to change file permissions for VPP binary API socket")
}

// configureVPP connects to VPP and configures it with common configuration needed for tests
func configureVPP(log *logrus.Logger) (vpp *vpplink.VppLink, uplinkSwIfIndex uint32) {
	// connect to VPP
	vpp, err := common.CreateVppLink("/tmp/"+VPPContainerName+"/vpp-api-test.sock",
		log.WithFields(logrus.Fields{"component": "vpp-api"}))
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Cannot create VPP client: %v", err))
	Expect(vpp).NotTo(BeNil())

	// setup common VRF setup
	for _, ipFamily := range vpplink.IpFamilies { //needed config for pod creation tests
		err := vpp.AddVRF(common.PuntTableId, ipFamily.IsIp6, fmt.Sprintf("punt-table-%s", ipFamily.Str))
		if err != nil {
			log.Fatal(errors.Wrapf(err, "Error creating punt vrf %s", ipFamily.Str))
		}
		err = vpp.AddVRF(common.PodVRFIndex, ipFamily.IsIp6, fmt.Sprintf("calico-pods-%s", ipFamily.Str))
		if err != nil {
			log.Fatal(err)
		}
		err = vpp.AddDefaultRouteViaTable(common.PodVRFIndex, common.DefaultVRFIndex, ipFamily.IsIp6)
		if err != nil {
			log.Fatal(err)
		}
	}

	// setup simplified mock version of uplink interface
	// Note: for the real configuration of the uplink interface and other related things see
	// UplinkDriver.CreateMainVppInterface(...) and VppRunner.configureVpp(...))
	uplinkSwIfIndex, err = vpp.CreateTapV2(&types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			HostInterfaceName: UplinkIfName,
			HardwareAddr:      mac("aa:bb:cc:dd:ee:01"),
		},
		Tag:   fmt.Sprintf("host-%s", UplinkIfName),
		Flags: types.TapFlagNone,
		// Host end of tap (it is located inside docker container)
		HostMtu:        1500,
		HostMacAddress: *mac("aa:bb:cc:dd:ee:02"),
	})
	Expect(err).ToNot(HaveOccurred(), "Error creating mocked Uplink interface")
	err = vpp.InterfaceAdminUp(uplinkSwIfIndex)
	Expect(err).ToNot(HaveOccurred(), "Error setting state to UP for mocked Uplink interface")
	err = vpp.AddInterfaceAddress(uplinkSwIfIndex, ipNet(UplinkIP+"/24"))
	Expect(err).ToNot(HaveOccurred(), "Error adding IPv4 address to data interface")
	err = vpp.AddInterfaceAddress(uplinkSwIfIndex, ipNet(UplinkIPv6+"/16"))
	Expect(err).ToNot(HaveOccurred(), "Error adding IPv6 address to data interface")
	err = exec.Command("docker", "exec", VPPContainerName, "ip", "address", "add",
		GatewayIP+"/24", "dev", UplinkIfName).Run()
	Expect(err).ToNot(HaveOccurred(), "Failed to set IPv4 address for host end of tap")
	err = exec.Command("docker", "exec", VPPContainerName, "ip", "address", "add",
		GatewayIPv6+"/16", "dev", UplinkIfName).Run()
	Expect(err).ToNot(HaveOccurred(), "Failed to set IPv6 address for host end of tap")
	err = exec.Command("docker", "exec", VPPContainerName, "ip", "link", "set",
		UplinkIfName, "up").Run()
	Expect(err).ToNot(HaveOccurred(), "Failed to set state to UP for host end of tap")

	return
}

// teardownVPP removes container with running VPP to stop VPP and clean after it
func teardownVPP() {
	err := exec.Command("docker", "rm", "-f", VPPContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to stop and remove VPP docker container")
}

// addIPPoolForCalicoClient is convenience function for adding IPPool to mocked Calico IPAM Stub used
// in Calico client stub. This function doesn't set anything for the watchers.IpamCache implementation.
func addIPPoolForCalicoClient(client *calico.CalicoClientStub, poolName string, poolCIRD string) (
	*apiv3.IPPool, error) {
	return client.IPPoolsStub.Create(nil, &apiv3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: poolName,
		},
		Spec: apiv3.IPPoolSpec{
			CIDR: poolCIRD,
		},
	}, options.SetOptions{})
}

func ipNet(ipNetCIDRStr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(ipNetCIDRStr)
	Expect(err).To(BeNil())
	return ipNet
}

func mac(macStr string) *net.HardwareAddr {
	mac, err := net.ParseMAC(macStr)
	Expect(err).To(BeNil())
	return &mac
}

func iptypesIP6Address(address string) ip_types.IP6Address {
	addr, err := ip_types.ParseAddress(address)
	Expect(err).ToNot(HaveOccurred(), "failed to parse ip_types.IP6Addess from string %s", addr)
	return addr.Un.GetIP6()
}

func sidArray(addresses ...ip_types.IP6Address) (sids [16]ip_types.IP6Address) {
	for i, address := range addresses {
		sids[i] = address
	}
	return sids
}
