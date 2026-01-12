package connectivity_test

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/testutils"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

// Names of integration tests arguments
const (
	VppImageArgName           = "VPP_IMAGE"
	VppBinaryArgName          = "VPP_BINARY"
	VppContainerExtraArgsName = "VPP_CONTAINER_EXTRA_ARGS"
)

type ipamStub struct{}

func (s *ipamStub) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	return false
}

func (s *ipamStub) GetPrefixIPPool(prefix *net.IPNet) *proto.IPAMPool {
	return nil
}

// TestConnectivityIntegration runs all the ginkgo integration test inside connectivity package
func TestConnectivityIntegration(t *testing.T) {
	// skip test if test run is not integration test run (prevent accidental run of integration tests using go test ./...)
	_, isIntegrationTestRun := os.LookupEnv(VppImageArgName)
	if !isIntegrationTestRun {
		t.Skip("skipping connectivity integration tests (set INTEGRATION_TEST env variable to run these tests)")
	}

	// integrate gomega and ginkgo -> register all Connectivity integration tests
	RegisterFailHandler(Fail)
	RunSpecs(t, "Connectivity Integration Suite")
}

var _ = BeforeSuite(func() {
	// extract common input for Connectivity integration tests
	var found bool
	testutils.VppImage, found = os.LookupEnv(VppImageArgName)
	if !found {
		Expect(testutils.VppImage).ToNot(BeEmpty(), fmt.Sprintf("Please specify docker image containing "+
			"VPP binary using %s environment variable.", VppImageArgName))
	}
	testutils.VppBinary, found = os.LookupEnv(VppBinaryArgName)
	if !found {
		Expect(testutils.VppBinary).ToNot(BeEmpty(), fmt.Sprintf("Please specify VPP binary (full path) "+
			"inside docker image %s using %s environment variable.", testutils.VppImage, VppBinaryArgName))
	}

	vppContainerExtraArgsList, found := os.LookupEnv(VppContainerExtraArgsName)
	if found {
		testutils.VppContainerExtraArgs = append(testutils.VppContainerExtraArgs, strings.Split(vppContainerExtraArgsList, ",")...)
	}

	// Parse environment variables to ensure config is initialized.
	// This prevents nil pointer dereferences in components that rely on config defaults (e.g. SRv6Provider).
	_ = config.ParseAllEnvVars()
})

var _ = Describe("Connectivity functionality", func() {
	var (
		log                *logrus.Logger
		vpp                *vpplink.VppLink
		connectivityServer *connectivity.ConnectivityServer
		t                  tomb.Tomb
	)

	BeforeEach(func() {
		log = logrus.New()

		// Initialize tomb early to ensure AfterEach doesn't hang on uninitialized tomb if BeforeEach panics
		t = tomb.Tomb{}

		// Set unique container name for Connectivity tests
		testutils.VPPContainerName = "connectivity-tests-vpp"
		testutils.StartVPP()
		vpp, _ = testutils.ConfigureVPP(log)

		// Initialize required components
		nodeName := "node1"
		config.NodeName = &nodeName
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		connectivityServer = connectivity.NewConnectivityServer(vpp, &ipamStub{}, nil, log.WithFields(logrus.Fields{"component": "connectivity"}))

		// Configure SNAT - this is required for the connectivity server to manage exclude prefixes
		err := vpp.CnatSetSnatAddresses(net.ParseIP("1.1.1.1"), net.ParseIP("f::f"))
		Expect(err).ToNot(HaveOccurred(),
			"failed to configure SNAT addresses")
		err = vpp.SetK8sSnatPolicy()
		Expect(err).ToNot(HaveOccurred(),
			"failed to configure SNAT policy")

		// Start the connectivity server - it listens to pubsub events and manages CNAT exclude prefixes
		go func() {
			_ = connectivityServer.ServeConnectivity(&t)
		}()
	})

	AfterEach(func() {
		t.Kill(nil)
		_ = t.Wait()

		// Clean up the symlink we created
		os.Remove("/run/vpp/stats.sock")
		// Clean up the VPP container
		testutils.TeardownVPP()
	})

	// Test that the connectivity server correctly manages CNAT exclude prefixes when peer nodes are added/removed.
	// This ensures that traffic to peer nodes bypasses SNAT by testing the connectivity server's response to
	// PeerNodeStateChanged events via pubsub, the mechanism used to manage CNAT exclude prefixes for peer nodes.
	It("should add and remove cnat exclude prefixes for peer nodes", func() {
		peerNode := &common.LocalNodeSpec{
			Name:        "host2",
			IPv4Address: common.FullyQualified(net.ParseIP("11.11.11.11")),
			IPv6Address: common.FullyQualified(net.ParseIP("f::d")),
		}

		By("adding a peer node and expecting exclude prefixes")
		common.SendEvent(common.CalicoVppEvent{
			Type: common.PeerNodeStateChanged,
			New:  peerNode,
		})
		Eventually(func() error {
			out, err := vpp.RunCli("show cnat snat")
			if err != nil {
				return err
			}
			if !strings.Contains(out, "11.11.11.11/32") {
				return fmt.Errorf("missing IPv4 exclude prefix: %s", out)
			}
			if !strings.Contains(out, "f::d/128") {
				return fmt.Errorf("missing IPv6 exclude prefix: %s", out)
			}
			return nil
		}, 5*time.Second, 100*time.Millisecond).Should(Succeed())

		By("removing a peer node and expecting exclude prefixes to be deleted")
		common.SendEvent(common.CalicoVppEvent{
			Type: common.PeerNodeStateChanged,
			Old:  peerNode,
		})
		Eventually(func() error {
			out, err := vpp.RunCli("show cnat snat")
			if err != nil {
				return err
			}
			if strings.Contains(out, "11.11.11.11/32") {
				return fmt.Errorf("unexpected IPv4 exclude prefix: %s", out)
			}
			if strings.Contains(out, "f::d/128") {
				return fmt.Errorf("unexpected IPv6 exclude prefix: %s", out)
			}
			return nil
		}, 5*time.Second, 100*time.Millisecond).Should(Succeed())
	})
})
