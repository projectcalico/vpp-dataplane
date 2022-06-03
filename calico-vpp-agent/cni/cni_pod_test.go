package cni_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

const (
	// PodMockContainerName is used container name for poo container mock
	PodMockContainerName = "vpp-cni-pod-mock"
	// PodMockImage is docker image used for pod mocking
	PodMockImage = "calicovpp/vpp-test-pod-mock:latest"
)

var _ = Describe("Pod-related functionality of CNI", func() {
	var (
		log       *logrus.Logger
		vpp       *vpplink.VppLink
		cniServer *cni.Server
	)

	BeforeEach(func() {
		log = logrus.New()
		startVPP()
		vpp, _ = configureVPP(log)

		// setup CNI server (functionality target of tests)
		ipam := watchers.NewIPAMCache(vpp, nil, log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		cniServer = cni.NewCNIServer(vpp, ipam, log.WithFields(logrus.Fields{"component": "cni"}))
		cniServer.SetFelixConfig(&config.Config{})
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		ipam.ForceReady()
	})

	Describe("Addition of the pod", func() {
		BeforeEach(func() {
			createPod()
		})

		Context("When new pod is added", func() {
			It("should have properly configured interface tunnel to VPP", func() {
				const (
					ipAddress     = "1.2.3.44"
					interfaceName = "newInterface"
				)

				By("Getting Pod mock container's PID")
				containerPidOutput, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}",
					PodMockContainerName).Output()
				Expect(err).Should(BeNil(), "Failed to get pod mock container's PID string")
				containerPidStr := strings.ReplaceAll(string(containerPidOutput), "\n", "")

				By("Adding pod using CNI server")
				newPod := &proto.AddRequest{
					InterfaceName: interfaceName,
					Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
					ContainerIps:  []*proto.IPConfig{{Address: ipAddress + "/24"}},
					Workload:      &proto.WorkloadIDs{},
				}
				reply, err := cniServer.Add(context.Background(), newPod)
				Expect(err).ToNot(HaveOccurred(), "Pod addition failed")
				Expect(reply.Successful).To(BeTrue(),
					fmt.Sprintf("Pod addition failed due to: %s", reply.ErrorMessage))

				By("Checking existence (and IP address) of interface tunnel at added pod's end")
				interfaceDetails, err := exec.Command("docker", "exec", PodMockContainerName,
					"ip", "address", "show", "dev", interfaceName).Output()
				Expect(err).Should(BeNil(), "Failed to get added interface details from pod container")
				Expect(string(interfaceDetails)).Should(ContainSubstring(ipAddress),
					"Interface tunnel on new pod's end is either wrong configured "+
						"for IP address or doesn't exist at all")

				By("Checking existence of interface tunnel at VPP's end")
				ifSwIfIndex, err := vpp.SearchInterfaceWithTag(
					interfaceTagForLocalTunTunnel(newPod.InterfaceName, newPod.Netns))
				Expect(err).ShouldNot(HaveOccurred(), "Failed to get interface at VPP's end")
				Expect(ifSwIfIndex).ToNot(Equal(vpplink.INVALID_SW_IF_INDEX),
					"No interface at VPP's end is found")
				Expect(ifSwIfIndex).NotTo(BeZero(), "No interface at VPP's end is found")

				By("Checking correct IP address of interface tunnel at VPP's end")
				couple, err := vpp.InterfaceGetUnnumbered(ifSwIfIndex)
				Expect(err).ShouldNot(HaveOccurred(), "Failed to retrieve unnumbered interface "+
					"info dump for VPP's end of interface tunnel")
				addrList, err := vpp.AddrList(uint32(couple.IPSwIfIndex), false)
				Expect(err).ShouldNot(HaveOccurred(),
					"Failed to get addresses for unnumbered interfaces")
				var correctAdress bool
				for _, addr := range addrList {
					if addr.IPNet.IP.Equal(net.ParseIP(ipAddress)) {
						correctAdress = true
					}
				}
				Expect(correctAdress).To(BeTrue(),
					"VPP's end of interface tunnel is not correctly configured for IP address")

				By("Checking correct MTU for tunnel interface at VPP's end")
				details, err := vpp.GetInterfaceDetails(ifSwIfIndex)
				Expect(err).ShouldNot(HaveOccurred(),
					"Failed to retrieve interface details of VPP's end of interface tunnel")
				Expect(int(details.Mtu[0])).To(Equal(vpplink.MAX_MTU),
					"VPP's end of interface tunnel has not correctly configured MTU")
			})
		})
		AfterEach(func() {
			teardownPod()
		})
	})

	AfterEach(func() {
		teardownVPP()
	})
})

// createPod creates docker container that will be used as pod for CNI testing
func createPod() {
	// docker container cleanup (failed test that didn't properly clean up docker containers?)
	err := exec.Command("docker", "rm", "-f", PodMockContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to clean up old pod mock docker container")

	// start new pod mock (docker container)
	err = exec.Command("docker", "run", "-d", "--network", "none", "--name", PodMockContainerName,
		PodMockImage, "sleep", "10d").Run()
	Expect(err).Should(BeNil(), "Failed to start new pod mock (docker container)")
}

// teardownPod removes container that is used as Pod mock
func teardownPod() {
	err := exec.Command("docker", "rm", "-f", PodMockContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to stop and remove pod mock (docker container)")
}

// interfaceTagForLocalTunTunnel constructs the tag for the VPP side of the tap tunnel the same way as cni server
func interfaceTagForLocalTunTunnel(interfaceName, netns string) string {
	return (&storage.LocalPodSpec{
		NetnsName:     netns,
		InterfaceName: interfaceName,
	}).GetInterfaceTag("tun" /* private name field of TunTapPodInterfaceDriver */)
}
