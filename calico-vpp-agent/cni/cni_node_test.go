package cni_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gs "github.com/onsi/gomega/gstruct"
	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/config"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
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
	UplinkIfName = "uplink"
	UplinkIP     = "10.0.100.1"
	GatewayIP    = "10.0.100.254"
)

// NodeTestsContainerName is used container name for node tests only
const NodeTestsContainerName = "vpp-cni-node-tests"

var _ = Describe("Node-related functionality of CNI", func() {
	var (
		log                *logrus.Logger
		vpp                *vpplink.VppLink
		connectivityServer *connectivity.ConnectivityServer
		uplinkSwIfIndex    uint32
	)

	BeforeEach(func() {
		log = logrus.New()
		startVPP()
		vpp, uplinkSwIfIndex = configureVPP(log)

		// setup connectivity server (functionality target of tests)
		ipam := watchers.NewIPAMCache(vpp, nil, log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		connectivityServer = connectivity.NewConnectivityServer(vpp, ipam, nil,
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
							"Gw": Equal(toGatewayAddressFormatOf(GatewayIP)),
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
		// TODO add all other ConnectivityProviders
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
	err := exec.Command("docker", "rm", "-f", NodeTestsContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to clean up old VPP docker container")

	// start VPP inside docker container
	err = exec.Command("docker", "run", "-d", "--privileged", "--name", NodeTestsContainerName,
		"-v", "/tmp/"+NodeTestsContainerName+":/var/run/vpp/",
		"-v", "/proc:/proc", // needed for manipulation of another docker container's network namespace
		"--entrypoint", vppBinary, vppImage,
		vppBinaryConfigArg).Run()
	Expect(err).Should(BeNil(), "Failed to start VPP inside docker container")

	time.Sleep(1 * time.Second) // TODO wait properly for socket to appear (<1s wait?)
	// fix file permissions for VPP binary socket exposed from docker container
	err = exec.Command("docker", "exec", NodeTestsContainerName, "chmod", "o+rw",
		"/var/run/vpp/vpp-api-test.sock").Run()
	Expect(err).Should(BeNil(), "Failed to change file permissions for VPP binary API socket")
}

// configureVPP connects to VPP and configures it with common configuration needed for tests
func configureVPP(log *logrus.Logger) (vpp *vpplink.VppLink, uplinkSwIfIndex uint32) {
	// connect to VPP
	vpp, err := common.CreateVppLink("/tmp/"+NodeTestsContainerName+"/vpp-api-test.sock",
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
	Expect(err).ToNot(HaveOccurred(), "Error adding address to data interface")
	err = exec.Command("docker", "exec", NodeTestsContainerName, "ip", "address", "add",
		GatewayIP+"/24", "dev", UplinkIfName).Run()
	Expect(err).ToNot(HaveOccurred(), "Failed to set address for host end of tap")
	err = exec.Command("docker", "exec", NodeTestsContainerName, "ip", "link", "set",
		UplinkIfName, "up").Run()
	Expect(err).ToNot(HaveOccurred(), "Failed to set state to UP for host end of tap")

	return
}

// teardownVPP removes container with running VPP to stop VPP and clean after it
func teardownVPP() {
	err := exec.Command("docker", "rm", "-f", NodeTestsContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to stop and remove VPP docker container")
}

// toGatewayAddressFormatOf converts IP address in string format to format that is returned by VPPLink
// by dumping routes from VPP. That format (i.e. []byte{10, 0, 100, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
// is strange as it can't be created by standard net package functions.
func toGatewayAddressFormatOf(ipAddress string) net.IP {
	tmp := [16]byte{}
	ip := net.ParseIP(ipAddress).To4()
	Expect(ip).ToNot(BeNil())
	copy(tmp[:], ip)
	return net.IP(tmp[:])
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
