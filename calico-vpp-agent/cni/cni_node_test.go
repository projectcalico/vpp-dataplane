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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
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
		client             *mocks.CalicoClientStub
		uplinkSwIfIndex    uint32
	)
	BeforeEach(func() {
		client = mocks.NewCalicoClientStub()
	})

	JustBeforeEach(func() {
		log = logrus.New()
		startVPP()
		vpp, uplinkSwIfIndex = configureVPP(log)

		// setup connectivity server (functionality target of tests)
		ipam := watchers.NewIPAMCache(vpp, client, log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		connectivityServer = connectivity.NewConnectivityServer(vpp, ipam, client,
			log.WithFields(logrus.Fields{"subcomponent": "connectivity"}))
		connectivityServer.SetOurBGPSpec(&oldv3.NodeBGPSpec{})
		connectivityServer.SetFelixConfig(&config.Config{})
		ipam.ForceReady() // needed for proper IPAM usage
	})

	Describe("Addition of the node", func() {
		Context("With FLAT connectivity", func() {
			It("should only configure correct routes in VPP", func() {
				By("Adding node")
				connectivityServer.UpdateIPConnectivity(&common.NodeConnectivity{
					Dst:              *ipNet("10.0.200.2/24"),
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
			// TODO impl IPSEC test
		})
		Context("With VXLAN connectivity", func() {
			// TODO impl VXLAN test
		})
		Context("With IP-IP connectivity", func() {
			// TODO impl IPIP test
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
				addIPPool(client, fmt.Sprintf("sr-localsids-pool-%s", agentConf.NodeName), "B::1:0/112")

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
					connectivityServer.SetOurBGPSpec(&oldv3.NodeBGPSpec{
						IPv4Address: ThisNodeIP + "/24",
						IPv6Address: ThisNodeIPv6 + "/128",
					})
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

// addIPPool is convenience function for adding IPPool to mocked Calico IPAM Stub
func addIPPool(client *mocks.CalicoClientStub, poolName string, poolCIRD string) (*apiv3.IPPool, error) {
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
