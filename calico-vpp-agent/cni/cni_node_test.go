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
	"context"
	"encoding/base64"
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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/tests/mocks"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/tests/mocks/calico"
	agentConf "github.com/projectcalico/vpp-dataplane/config/config"
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
	VppContainerExtraArgsName    = "VPP_CONTAINER_EXTRA_ARGS"
)

var (
	// vppImage is the name of docker image containing VPP binary
	vppImage string
	// vppBinary is the full path to VPP binary inside docker image
	vppBinary string
	// vppContainerExtraArgs is a list of additionnal cli parameters for the VPP `docker run ...`
	vppContainerExtraArgs []string = []string{}
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

	vppContainerExtraArgsList, found := os.LookupEnv(VppContainerExtraArgsName)
	if found {
		for _, arg := range strings.Split(vppContainerExtraArgsList, ",") {
			vppContainerExtraArgs = append(vppContainerExtraArgs, arg)
		}
	}

})

// Common setup constants
const (
	ThisNodeName = "node1"
	UplinkIfName = "uplink"
	UplinkIP     = "10.0.100.1"
	UplinkIPv6   = "A::1:1"
	GatewayIP    = "10.0.100.254"
	GatewayIPv6  = "A::1:254"
	ThisNodeIP   = UplinkIP
	ThisNodeIPv6 = UplinkIPv6

	AddedNodeName = "node2"
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
		felixConfig        *config.Config
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
		if felixConfig == nil {
			felixConfig = &config.Config{}
		}
		connectivityServer.SetFelixConfig(felixConfig)
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
				ipamStub.AddPrefixIPPool(ipNet(AddedNodeIP+"/24"), &proto.IPAMPoolUpdate{
					Id: fmt.Sprintf("custom-test-pool-for-ipsec-%s", AddedNodeIP+"/24"),
					Pool: &proto.IPAMPool{
						Cidr:     AddedNodeIP + "/24",
						IpipMode: encap.Always,
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
			// TODO test multiple IPSec tunnels (there is a option to created a group of IPSec tunnels at once)

			// FIXME This is partial test due to not simulating second IPSec node where the IPSec tunnel should end.
			//  The IPSec implementation in VPP can't negotiate with the other IPSec tunnel end node anything, so
			//  probably that is the reason why VPP is not showing all possible IPSec configuration as it usually does
			//  when the IPSec tunnel is up and running between 2 nodes.
			//  => not testing all IPSec settings, IPSec's IPIP tunnel being in UP state, test existence of
			//  route to each IPSec tunnel (1 multipath route)
			It("should have setup IPIP tunnel as backend and all IPSec settings (only PARTIAL test!)", func() {
				//Note: not testing setting of IPsecAsyncMode and threads dedicated to IPSec (CryptoWorkers)
				// inside RescanState() function call
				By("Adding node")
				configureBGPNodeIPAddresses(connectivityServer)
				// FIXME The concept of Destination and NextHop in common.NodeConnectivity is not well defined
				//  (is the Destination the IP of added node, or it subnet or totally unrelated network? Is
				//  the nexthop the IP of added node or could it be IP of some intermediate router that is
				//  sitting between nodes?). Hence the interpretation differs between connectivity providers.
				//  Need to either define it well(unify it?) and fix connectivity providers(and tests) or leave it
				//  in connectivity provider implementation and check each test for semantics used in given
				//  connectivity provider
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet(AddedNodeIP + "/24"),
					NextHop:          net.ParseIP(AddedNodeIP), // next hop == other node IP (for IPSec impl)
					ResolvedProvider: connectivity.IPSEC,
					Custom:           nil,
				}, false)

				By("Checking IP-IP tunnel")
				tunnels, err := vpp.ListIPIPTunnels()
				Expect(err).ToNot(HaveOccurred(),
					"Failed to get IP-IP tunnels from VPP (for IPSec checking)")
				ipipSwIfIndex, err := vpp.SearchInterfaceWithName("ipip0")
				Expect(err).ToNot(HaveOccurred(), "can't find ipip tunnel interface")
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
				assertUnnumberedInterface(ipipSwIfIndex, "IPSec's IPIP tunnel interface", vpp)

				By("checking IPSec's IPIP tunnel interface attributes (GSO+CNAT)")
				assertInterfaceGSOCNat(ipipSwIfIndex, "IPSec's IPIP tunnel interface", vpp)

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
				ipamStub.AddPrefixIPPool(ipNet(AddedNodeIP+"/24"), &proto.IPAMPoolUpdate{
					Id: fmt.Sprintf("custom-test-pool-for-vxlan-%s", AddedNodeIP+"/24"),
					Pool: &proto.IPAMPool{
						Cidr:      AddedNodeIP + "/24",
						VxlanMode: encap.Always,
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
					Dst:              *ipNet(AddedNodeIP + "/24"),
					NextHop:          net.ParseIP(GatewayIP),
					ResolvedProvider: connectivity.VXLAN,
					Custom:           nil,
				}, false)

				By("Checking VXLAN tunnel")
				vxlanSwIfIndex, err := vpp.SearchInterfaceWithName("vxlan_tunnel0")
				Expect(err).ToNot(HaveOccurred(), "can't find VXLAN tunnel interface")
				tunnels, err := vpp.ListVXLanTunnels()
				Expect(err).ToNot(HaveOccurred(), "Failed to get VXLAN tunnels from VPP")
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
				assertUnnumberedInterface(vxlanSwIfIndex, "VXLAN tunnel interface", vpp)

				By("checking VXLAN tunnel interface attributes (GSO+CNAT)")
				assertInterfaceGSOCNat(vxlanSwIfIndex, "VXLAN tunnel interface", vpp)

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
				ipamStub.AddPrefixIPPool(ipNet(AddedNodeIP+"/24"), &proto.IPAMPoolUpdate{
					Id: fmt.Sprintf("custom-test-pool-for-ipip-%s", AddedNodeIP+"/24"),
					Pool: &proto.IPAMPool{
						Cidr:     AddedNodeIP + "/24",
						IpipMode: encap.Always,
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
					Dst:              *ipNet(AddedNodeIP + "/24"),
					NextHop:          net.ParseIP(GatewayIP),
					ResolvedProvider: connectivity.IPIP,
					Custom:           nil,
				}, false)

				By("Checking IP-IP tunnel")
				ipipSwIfIndex, err := vpp.SearchInterfaceWithName("ipip0")
				Expect(err).ToNot(HaveOccurred(), "can't find ipip tunnel interface")
				tunnels, err := vpp.ListIPIPTunnels()
				Expect(err).ToNot(HaveOccurred(), "Failed to get IP-IP tunnels from VPP")
				Expect(tunnels).To(ContainElements(&types.IPIPTunnel{
					Src:       net.ParseIP(ThisNodeIP).To4(), // set by configureBGPNodeIPAddresses() call
					Dst:       net.ParseIP(GatewayIP).To4(),
					TableID:   0, // not filled -> used default VRF table
					SwIfIndex: ipipSwIfIndex,
				}))

				By("checking IPIP tunnel interface attributes (Unnumbered)")
				assertUnnumberedInterface(ipipSwIfIndex, "IPIP tunnel interface", vpp)

				By("checking IPIP tunnel interface attributes (GSO+CNAT)")
				assertInterfaceGSOCNat(ipipSwIfIndex, "IPIP tunnel interface", vpp)

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
			BeforeEach(func() {
				// setup felix config for Wireguard configuration
				felixConfig.WireguardEnabled = true
				felixConfig.WireguardListeningPort = 11111

				// setup PubSub handler to catch TunnelAdded events
				pubSubHandlerMock = mocks.NewPubSubHandlerMock(common.TunnelAdded)
				pubSubHandlerMock.Start()

				// configure this node's name and make Calico info data holder for it
				agentConf.NodeName = ThisNodeName
				client.Nodes().Create(context.Background(), &oldv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: agentConf.NodeName,
					},
				}, options.SetOptions{})

				// configure added node for wireguard public crypto key
				client.Nodes().Create(context.Background(), &oldv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: agentConf.NodeName,
					},
				}, options.SetOptions{})
			})

			// TODO test removal of wireguard tunnel

			It("must configure wireguard tunnel with one peer and routes to it", func() {
				By("Adding node")
				configureBGPNodeIPAddresses(connectivityServer)
				connectivityServer.ForceProviderEnableDisable(connectivity.WIREGUARD, true) // creates the tunnel (this is normally called by Felix config change event handler)
				addedNodePublicKey := "public-key-for-added-node"                           // max 32 characters due to VPP binapi
				connectivityServer.ForceNodeAddition(oldv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: AddedNodeName,
					},
					Status: oldv3.NodeStatus{
						WireguardPublicKey: base64.StdEncoding.EncodeToString([]byte(addedNodePublicKey)),
					},
				}, net.ParseIP(AddedNodeIP))
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet(AddedNodeIP + "/24"),
					NextHop:          net.ParseIP(AddedNodeIP), // wireguard impl uses nexthop as node IP
					ResolvedProvider: connectivity.WIREGUARD,
					Custom:           nil,
				}, false)

				By("checking wireguard tunnel")
				wireguardSwIfIndex, err := vpp.SearchInterfaceWithName("wg0")
				Expect(err).ToNot(HaveOccurred(), "can't find wireguard tunnel interface")
				wgTunnel, err := vpp.GetWireguardTunnel(wireguardSwIfIndex)
				Expect(err).ToNot(HaveOccurred(), "can't get wireguard tunnel from VPP")
				Expect(wgTunnel.Port).To(Equal(uint16(felixConfig.WireguardListeningPort)),
					"incorrectly set wireguard listening port")
				Expect(wgTunnel.Addr).To(Equal(net.ParseIP(ThisNodeIP).To4()),
					"incorrectly set IP address of this node's wireguard tunnel interface")

				By("checking wireguard tunnel interface attributes (Unnumbered)")
				assertUnnumberedInterface(wireguardSwIfIndex, "wireguard tunnel interface", vpp)

				By("checking wireguard tunnel interface attributes (GSO+CNAT)")
				assertInterfaceGSOCNat(wireguardSwIfIndex, "wireguard tunnel interface", vpp)

				By("checking wireguard tunnel interface attributes (Up state)")
				interfaceDetails, err := vpp.GetInterfaceDetails(wireguardSwIfIndex)
				Expect(err).ToNot(HaveOccurred(), "can't get wireguard tunnel interface's basic attributes")
				Expect(interfaceDetails.IsUp).To(BeTrue(), "wireguard tunnel interface should be in UP state")

				By("checking pushing of TunnelAdded event")
				// Note: VPP configuration done by receiver of this event is out of scope for this test
				Expect(pubSubHandlerMock.ReceivedEvents).To(ContainElement(common.CalicoVppEvent{
					Type: common.TunnelAdded,
					New:  wireguardSwIfIndex,
				}))

				By("checking remembering of public key for wireguard tunnel in calico configuration")
				// Note: public/private key is created by VPP (connectivity server sends empty public/private
				// keys but retrieves it back properly filled)
				thisNode, err := client.Nodes().Get(context.Background(), agentConf.NodeName, options.GetOptions{})
				Expect(err).ToNot(HaveOccurred(),
					"can't get this node info from mocked node info storage")
				Expect(thisNode.Status).ToNot(BeNil(),
					"public crypto key is not properly exposed in calico configuration")
				Expect(thisNode.Status.WireguardPublicKey).To(Equal(base64.StdEncoding.EncodeToString(wgTunnel.PublicKey)),
					"public crypto key is not properly exposed in calico configuration "+
						"(-> other nodes setuping wireguard can't use it and setup peer with this node)")

				By("checking wireguard peer")
				peers, err := vpp.ListWireguardPeers()
				Expect(thisNode.Status).ToNot(BeNil(),
					"can't get wireguard peers from VPP")
				Expect(peers).To(ContainElement(gs.PointTo(
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"PublicKey":  Equal(addPaddingTo32Bytes([]byte(addedNodePublicKey))),
						"Port":       Equal(uint16(felixConfig.WireguardListeningPort)),
						"TableID":    Equal(uint32(0)), // default table
						"Addr":       Equal(net.ParseIP(AddedNodeIP).To4()),
						"SwIfIndex":  Equal(wireguardSwIfIndex),
						"AllowedIps": ContainElements(*ipNet(AddedNodeIP + "/32")),
					}),
				)))

				By("checking wireguard routes to tunnel")
				routes, err := vpp.GetRoutes(common.PodVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for Pod VRF")
				Expect(routes).To(ContainElements(
					// when wireguard is created it makes steering route with for NextHop/<max CIRD mask length> from Pod VRF
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(AddedNodeIP + "/32"))),
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(wireguardSwIfIndex),
						})),
					})))
				routes, err = vpp.GetRoutes(common.DefaultVRFIndex, false)
				Expect(err).ToNot(HaveOccurred(), "Failed to get routes from VPP for default VRF")
				Expect(routes).To(ContainElements(
					// steering route for NodeConnectivity.Dst using wireguard tunnel that is leading to the added node
					gs.MatchFields(gs.IgnoreExtras, gs.Fields{
						"Dst": gs.PointTo(Equal(*ipNet(AddedNodeIP + "/24"))), // NodeConnectivity.Dst
						"Paths": ContainElements(gs.MatchFields(gs.IgnoreExtras, gs.Fields{
							"SwIfIndex": Equal(wireguardSwIfIndex),
						})),
					}),
				), "Can't find 2 routes that should steer the traffic to newly added node")
			})

			AfterEach(func() {
				if pubSubHandlerMock != nil {
					Expect(pubSubHandlerMock.Stop()).ToNot(HaveOccurred(),
						"can't properly stop mock of PubSub's handler")
				}
				felixConfig = nil // cleanup for next tests
			})
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
				agentConf.NodeName = ThisNodeName

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
						NextHop:          net.ParseIP(AddedNodeIPv6),
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
	cmd := []string{"run", "-d", "--privileged", "--name", VPPContainerName,
		"-v", "/tmp/" + VPPContainerName + ":/var/run/vpp/",
		"-v", "/proc:/proc", // needed for manipulation of another docker container's network namespace
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0"} // enable IPv6 in container (to set IPv6 on host's end of uplink)
	cmd = append(cmd, vppContainerExtraArgs...)
	cmd = append(cmd, "--entrypoint", vppBinary, vppImage, vppBinaryConfigArg)
	err = exec.Command("docker", cmd...).Run()
	Expect(err).Should(BeNil(), "Failed to start VPP inside docker container")
}

// configureVPP connects to VPP and configures it with common configuration needed for tests
func configureVPP(log *logrus.Logger) (vpp *vpplink.VppLink, uplinkSwIfIndex uint32) {
	// connect to VPP
	vpp, err := common.CreateVppLinkInRetryLoop("/tmp/"+VPPContainerName+"/vpp-api-test.sock",
		log.WithFields(logrus.Fields{"component": "vpp-api"}), 20*time.Second, 100*time.Millisecond)
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

// assertUnnumberedInterface checks whether the provided interface is unnumbered and properly takes IP address
// from the correct interface (conf.DataInterfaceSwIfIndex).
func assertUnnumberedInterface(swIfIndex uint32, interfaceDescriptiveName string, vpp *vpplink.VppLink) {
	unnumberedDetails, err := vpp.InterfaceGetUnnumbered(swIfIndex)
	Expect(err).ToNot(HaveOccurred(),
		fmt.Sprintf("can't get unnumbered details of %s", interfaceDescriptiveName))
	Expect(unnumberedDetails).ToNot(BeEmpty(), "can't find unnumbered interface")
	Expect(unnumberedDetails[0].IPSwIfIndex).To(Equal(
		interface_types.InterfaceIndex(agentConf.DataInterfaceSwIfIndex)),
		fmt.Sprintf("Unnumberred %s doesn't get IP address from expected interface", interfaceDescriptiveName))
}

// assertInterfaceGSOCNat check whether the given interface has properly set the GSO and CNAT attributes
func assertInterfaceGSOCNat(swIfIndex uint32, interfaceDescriptiveName string, vpp *vpplink.VppLink) {
	// Note: no specialized binary api or VPP CLI for getting GSO on interface -> using
	// Feature Arcs (https://wiki.fd.io/view/VPP/Feature_Arcs) to detect it (GSO is using them to steer
	// traffic), Feature Arcs have no binary API -> using VPP's VPE binary API
	featuresStr, err := vpp.RunCli(fmt.Sprintf("sh interface %d features", swIfIndex))
	Expect(err).ToNot(HaveOccurred(),
		fmt.Sprintf("failed to get %s's configured features", interfaceDescriptiveName))
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

func configureBGPNodeIPAddresses(connectivityServer *connectivity.ConnectivityServer) {
	connectivityServer.SetOurBGPSpec(&oldv3.NodeBGPSpec{
		IPv4Address: ThisNodeIP + "/24",
		IPv6Address: ThisNodeIPv6 + "/128",
	})
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

func ipNetWithIPInIPv6Format(ipNetCIDRStr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(ipNetCIDRStr)
	ipNet.IP = ipNet.IP.To16()
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

func addPaddingTo32Bytes(value []byte) []byte {
	result := [32]byte{}
	copy(result[:], value)
	return result[:]
}
