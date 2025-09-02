// Copyright (C) 2019 Cisco Systems Inc.
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

package testutils

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containernetworking/plugins/pkg/ns"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/connectivity"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/tests/mocks/calico"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/multinet-monitor/multinettypes"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PodMockContainerName is used container name for pod container mock
	PodMockContainerName = "cni-tests-pod-mock"
	// PodMockImage is docker image used for pod mocking
	PodMockImage              = "calicovpp/vpp-test-pod-mock:latest"
	VPPContainerName          = "cni-tests-vpp"
	VppContainerExtraArgsName = "VPP_CONTAINER_EXTRA_ARGS"
	ThisNodeName              = "node1"
	UplinkIfName              = "uplink"
	UplinkIP                  = "10.0.100.1"
	UplinkIPv6                = "A::1:1"
	GatewayIP                 = "10.0.100.254"
	GatewayIPv6               = "A::1:254"
	ThisNodeIP                = UplinkIP
	ThisNodeIPv6              = UplinkIPv6

	AddedNodeName = "node2"
	AddedNodeIP   = "10.0.200.1"
	AddedNodeIPv6 = "A::2:1"
)

var (
	// VppImage is the name of docker image containing VPP binary
	VppImage string
	// VppBinary is the full path to VPP binary inside docker image
	VppBinary string
	// vppContainerExtraArgs is a list of additionnal cli parameters for the VPP `docker run ...`
	VppContainerExtraArgs []string = []string{}
)

func AssertTunInterfaceExistence(vpp *vpplink.VppLink, podSpec *model.LocalPodSpec) uint32 {
	ifSwIfIndex, err := vpp.SearchInterfaceWithTag(
		InterfaceTagForLocalTunTunnel(podSpec.InterfaceName, podSpec.NetnsName))
	Expect(err).ShouldNot(HaveOccurred(), "Failed to get interface at VPP's end")
	Expect(ifSwIfIndex).ToNot(Equal(vpplink.InvalidSwIfIndex),
		"No interface at VPP's end is found")
	Expect(ifSwIfIndex).NotTo(BeZero(), "No interface at VPP's end is found")
	return ifSwIfIndex
}

func AssertTunnelInterfaceIPAddress(vpp *vpplink.VppLink, ifSwIfIndex uint32, expectedIPAddress string) {
	couples, err := vpp.InterfaceGetUnnumbered(ifSwIfIndex)
	Expect(err).ShouldNot(HaveOccurred(), "Failed to retrieve unnumbered interface "+
		"info dump for VPP's end of interface tunnel")
	Expect(couples).ToNot(BeEmpty(), "can't find unnumbered interface")
	addrList, err := vpp.AddrList(uint32(couples[0].IPSwIfIndex), false)
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to get addresses for unnumbered interfaces")
	var correctAdress bool
	for _, addr := range addrList {
		if addr.IPNet.IP.Equal(net.ParseIP(expectedIPAddress)) {
			correctAdress = true
		}
	}
	Expect(correctAdress).To(BeTrue(),
		"VPP's end of interface tunnel is not correctly configured for IP address")
}

func AssertTunnelInterfaceMTU(vpp *vpplink.VppLink, ifSwIfIndex uint32) {
	details, err := vpp.GetInterfaceDetails(ifSwIfIndex)
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to retrieve interface details of VPP's end of interface tunnel")
	Expect(int(details.Mtu[0])).To(Equal(vpplink.CalicoVppMaxMTu),
		"VPP's end of interface tunnel has not correctly configured MTU")
}

// assertInterfaceGSOCNat check whether the given interface has properly set the GSO and CNAT attributes
func AssertInterfaceGSO(swIfIndex uint32, interfaceDescriptiveName string, vpp *vpplink.VppLink) {
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
}

// AssertRPFVRFExistence checks that dedicated VRF for RPF is created for interface in VPP
func AssertRPFVRFExistence(vpp *vpplink.VppLink, interfaceName string, netnsName string) uint32 {
	VRFs, err := vpp.ListVRFs()
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to retrieve list of VRFs in VPP")
	hbytes := sha512.Sum512([]byte(fmt.Sprintf("%s%s%s%s", "4", netnsName, interfaceName, "RPF")))
	h := base64.StdEncoding.EncodeToString(hbytes[:])[:config.VrfTagHashLen]
	s := fmt.Sprintf("%s-%s-%sRPF-%s", h, "4", interfaceName, filepath.Base(netnsName))
	vrfTag := config.TruncateStr(s, config.MaxAPITagLen)
	foundRPFVRF := false
	var vrfID uint32
	for _, VRF := range VRFs {
		if VRF.Name == vrfTag {
			foundRPFVRF = true
			vrfID = VRF.VrfID
			break
		}
	}
	Expect(foundRPFVRF).Should(BeTrue(),
		"Failed to find RPF VRF for interface")
	return vrfID
}

// AssertRPFRoutes checks that a route to the pod is added in the RPFVRF and to addresses allowed
// to be spoofed
func AssertRPFRoutes(vpp *vpplink.VppLink, vrfID uint32, swifindex uint32, ipAddress string) {
	routes, err := vpp.GetRoutes(vrfID, false)
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to get routes from RPF VRF")
	Expect(routes).To(ContainElements(
		types.Route{
			Dst: IPNet(ipAddress + "/32"),
			Paths: []types.RoutePath{{
				SwIfIndex: swifindex,
				Gw:        IPNet(ipAddress + "/32").IP,
			}},
			Table: vrfID,
		},
		types.Route{
			Dst: IPNet("172.16.104.7" + "/32"),
			Paths: []types.RoutePath{{
				SwIfIndex: swifindex,
				Gw:        IPNet(ipAddress + "/32").IP,
			}},
			Table: vrfID,
		},
		types.Route{
			Dst: IPNet("3.4.5.6" + "/32"),
			Paths: []types.RoutePath{{
				SwIfIndex: swifindex,
				Gw:        IPNet(ipAddress + "/32").IP,
			}},
			Table: vrfID,
		},
	), "Cannot find route to pod in RPF VRF %s", ipAddress)

}

// CreatePod creates docker container that will be used as pod for CNI testing
func CreatePod() {
	// docker container cleanup (failed test that didn't properly clean up docker containers?)
	err := exec.Command("docker", "rm", "-f", PodMockContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to clean up old pod mock docker container")

	// start new pod mock (docker container)
	err = exec.Command("docker", "run", "-d", "--network", "none", "--name", PodMockContainerName,
		PodMockImage, "sleep", "10d").Run()
	Expect(err).Should(BeNil(), "Failed to start new pod mock (docker container)")
}

// TeardownPod removes container that is used as Pod mock
func TeardownPod() {
	err := exec.Command("docker", "rm", "-f", PodMockContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to stop and remove pod mock (docker container)")
}

// RunInPod runs runner function in provided pod network namespace. This is the same as running
// networking commands inside pod.
func RunInPod(podNetNS string, runner func()) {
	err := ns.WithNetNSPath(podNetNS, func(hostNS ns.NetNS) error {
		defer GinkgoRecover() // running in different goroutine -> needed for failed assertion retrieval
		runner()
		return nil
	})
	Expect(err).Should(BeNil(), "Failed to runInPod")
}

// DpoNetworkNameFieldName extracts JSON field name for NetworkName used in proto.AddRequest.DataplaneOptions
func DpoNetworkNameFieldName() string {
	netNameField, found := reflect.TypeOf(multinettypes.NetConf{}.DpOptions).FieldByName("NetName")
	Expect(found).To(BeTrue(),
		"can't find network name field in NetworkAttachmentDefinition. Did that structure changed?")
	jsonStr, isSet := netNameField.Tag.Lookup("json")
	Expect(isSet).To(BeTrue(), "can't find json name for network name field in NetworkAttachmentDefinition")
	return strings.Split(jsonStr, ",")[0]
}

// InterfaceTagForLocalTunTunnel constructs the tag for the VPP side of the tap tunnel the same way as cni server
func InterfaceTagForLocalTunTunnel(interfaceName, netns string) string {
	return InterfaceTagForLocalTunnel(
		podinterface.NewTunTapPodInterfaceDriver(nil, nil, nil).Name,
		interfaceName, netns)
}

// InterfaceTagForLocalMemifTunnel constructs the tag for the VPP side of the memif tunnel the same way as cni server
func InterfaceTagForLocalMemifTunnel(interfaceName, netns string) string {
	return InterfaceTagForLocalTunnel(podinterface.NewMemifPodInterfaceDriver(nil, nil).Name,
		interfaceName, netns)
}

// InterfaceTagForLocalTunnel constructs the tag for the VPP side of the local tunnel the same way as cni server
func InterfaceTagForLocalTunnel(prefix, interfaceName, netns string) string {
	return (&model.LocalPodSpec{
		NetnsName:     netns,
		InterfaceName: interfaceName,
	}).GetInterfaceTag(prefix)
}

// FirstIPinIPRange computes first usable IPv4 address from the given subnet. The subnet definition IP address
// (ending with zero bits) is not considered as usable IPv4 address as it can have special meaning in certain situations.
func FirstIPinIPRange(ipRangeCIDR string) net.IP {
	ip, _, err := net.ParseCIDR(ipRangeCIDR)
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("can't parse range subnet string %s as CIDR", ipRangeCIDR))
	ip = ip.To4() // expecting IPv4 address
	ip[3]++       // incrementing last IP address byte to get the first usable IP address in subnet range (subnet x.y.z.0 -> first ip address x.y.z.1)
	return ip
}

// PodVRFs gets ids of IPv4 and IPv6 pod-specific VRFs from VPP
func PodVRFs(podInterface, podNetNSName string, vpp *vpplink.VppLink) (vrf4ID, vrf6ID uint32, err error) {
	vrfs, err := vpp.ListVRFs()
	Expect(err).ToNot(HaveOccurred(), "error listing VRFs to find all pod VRFs")

	podSpec := model.LocalPodSpec{
		InterfaceName:      podInterface,
		NetnsName:          podNetNSName,
		LocalPodSpecStatus: *model.NewLocalPodSpecStatus(),
	}
	for _, vrf := range vrfs {
		for _, ipFamily := range vpplink.IPFamilies {
			if vrf.Name == podSpec.GetVrfTag(ipFamily, "") {
				podSpec.SetVrfID(vrf.VrfID, ipFamily)
			}
		}
		if podSpec.V4VrfID != types.InvalidID && podSpec.V6VrfID != types.InvalidID {
			return podSpec.V4VrfID, podSpec.V6VrfID, nil
		}
	}

	if (podSpec.V4VrfID != types.InvalidID) != (podSpec.V6VrfID != types.InvalidID) {
		return podSpec.V4VrfID, podSpec.V6VrfID,
			fmt.Errorf("partial VRF state v4=%d v6=%d key=%s", podSpec.V4VrfID, podSpec.V6VrfID, podSpec.Key())
	}

	return podSpec.V4VrfID, podSpec.V6VrfID, fmt.Errorf("not VRFs state (key=%s)", podSpec.Key())
}

func IPFamilyIndex(ipFamily vpplink.IPFamily) int {
	for idx, family := range vpplink.IPFamilies {
		if family == ipFamily {
			return idx
		}
	}
	return math.MaxInt
}

// StartVPP creates docker container and runs inside the VPP
func StartVPP() {
	// prepare VPP configuration
	vppBinaryConfigArg := `unix {
			nodaemon
			full-coredump
			cli-listen /var/run/vpp/cli.sock
			pidfile /run/vpp/vpp.pid
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

	wd, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred(), "Failed to get working directory")
	repoDir := strings.TrimSpace(filepath.Join(wd, "../.."))
	// start VPP inside docker container
	cmdParams := []string{"run", "-d", "--privileged", "--name", VPPContainerName,
		"-v", "/tmp/" + VPPContainerName + ":/var/run/vpp/",
		"-v", "/proc:/proc", // needed for manipulation of another docker container's network namespace
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0", // enable IPv6 in container (to set IPv6 on host's end of uplink)
		"-v", repoDir + ":/repo/",
		"--pid=host",
		"--env", fmt.Sprintf("LD_LIBRARY_PATH=%s", os.Getenv("LD_LIBRARY_PATH")),
	}
	cmdParams = append(cmdParams, VppContainerExtraArgs...)
	cmdParams = append(cmdParams, "--entrypoint", VppBinary, VppImage, vppBinaryConfigArg)
	cmd := exec.Command("docker", cmdParams...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	Expect(err).Should(BeNil(), "Failed to start VPP inside docker container")
}

// ConfigureVPP connects to VPP and configures it with common configuration needed for tests
func ConfigureVPP(log *logrus.Logger) (vpp *vpplink.VppLink, uplinkSwIfIndex uint32) {
	// connect to VPP
	vpp, err := common.CreateVppLinkInRetryLoop("/tmp/"+VPPContainerName+"/vpp-api-test.sock",
		log.WithFields(logrus.Fields{"component": "vpp-api"}), 20*time.Second, 100*time.Millisecond)
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Cannot create VPP client: %v", err))
	Expect(vpp).NotTo(BeNil())

	// setup common VRF setup
	for _, ipFamily := range vpplink.IPFamilies { //needed config for pod creation tests
		err := vpp.AddVRF(common.PuntTableID, ipFamily.IsIP6, fmt.Sprintf("punt-table-%s", ipFamily.Str))
		if err != nil {
			log.Fatal(errors.Wrapf(err, "Error creating punt vrf %s", ipFamily.Str))
		}
		err = vpp.AddVRF(common.PodVRFIndex, ipFamily.IsIP6, fmt.Sprintf("calico-pods-%s", ipFamily.Str))
		if err != nil {
			log.Fatal(err)
		}
		err = vpp.AddDefaultRouteViaTable(common.PodVRFIndex, common.DefaultVRFIndex, ipFamily.IsIP6)
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
			HardwareAddr:      Mac("aa:bb:cc:dd:ee:01"),
		},
		Tag:   fmt.Sprintf("main-%s", UplinkIfName),
		Flags: types.TapFlagNone,
		// Host end of tap (it is located inside docker container)
		HostMtu:        1500,
		HostMacAddress: Mac("aa:bb:cc:dd:ee:02"),
	})
	Expect(err).ToNot(HaveOccurred(), "Error creating mocked Uplink interface")
	err = vpp.InterfaceAdminUp(uplinkSwIfIndex)
	Expect(err).ToNot(HaveOccurred(), "Error setting state to UP for mocked Uplink interface")
	err = vpp.AddInterfaceAddress(uplinkSwIfIndex, IPNet(UplinkIP+"/24"))
	Expect(err).ToNot(HaveOccurred(), "Error adding IPv4 address to data interface")
	err = vpp.AddInterfaceAddress(uplinkSwIfIndex, IPNet(UplinkIPv6+"/16"))
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

// TeardownVPP removes container with running VPP to stop VPP and clean after it
func TeardownVPP() {
	err := exec.Command("docker", "rm", "-f", VPPContainerName).Run()
	Expect(err).Should(BeNil(), "Failed to stop and remove VPP docker container")
}

// AssertUnnumberedInterface checks whether the provided interface is unnumbered and properly takes IP address
// from the correct interface (VppManagerInfo.GetMainSwIfIndex()).
func AssertUnnumberedInterface(swIfIndex uint32, interfaceDescriptiveName string, vpp *vpplink.VppLink) {
	unnumberedDetails, err := vpp.InterfaceGetUnnumbered(swIfIndex)
	Expect(err).ToNot(HaveOccurred(),
		fmt.Sprintf("can't get unnumbered details of %s", interfaceDescriptiveName))
	Expect(unnumberedDetails).ToNot(BeEmpty(), "can't find unnumbered interface")
	Expect(unnumberedDetails[0].IPSwIfIndex).To(Equal(
		interface_types.InterfaceIndex(common.VppManagerInfo.GetMainSwIfIndex())),
		fmt.Sprintf("Unnumberred %s doesn't get IP address from expected interface", interfaceDescriptiveName))
}

// AssertInterfaceGSOCNat check whether the given interface has properly set the GSO and CNAT attributes
func AssertInterfaceGSOCNat(swIfIndex uint32, interfaceDescriptiveName string, vpp *vpplink.VppLink) {
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

// AssertNextNodeLink asserts that in VPP graph the given node has linked the linkedNextNode as one of its
// "next" nodes for processing. It returns to node specific index of the checked next node.
func AssertNextNodeLink(node, linkedNextNode string, vpp *vpplink.VppLink) int {
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

func ConfigureBGPNodeIPAddresses(connectivityServer *connectivity.ConnectivityServer) {
	ip4, ip4net, _ := net.ParseCIDR(ThisNodeIP + "/24")
	ip4net.IP = ip4
	ip6, ip6net, _ := net.ParseCIDR(ThisNodeIPv6 + "/128")
	ip6net.IP = ip6
	connectivityServer.SetOurBGPSpec(&common.LocalNodeSpec{
		IPv4Address: ip4net,
		IPv6Address: ip6net,
	})
}

// AddIPPoolForCalicoClient is convenience function for adding IPPool to mocked Calico IPAM Stub used
// in Calico client stub. This function doesn't set anything for the watchers.IpamCache implementation.
func AddIPPoolForCalicoClient(client *calico.CalicoClientStub, poolName string, poolCIRD string) (
	*apiv3.IPPool, error) {
	return client.IPPoolsStub.Create(context.Background(), &apiv3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: poolName,
		},
		Spec: apiv3.IPPoolSpec{
			CIDR: poolCIRD,
		},
	}, options.SetOptions{})
}

func IPNet(ipNetCIDRStr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(ipNetCIDRStr)
	Expect(err).To(BeNil())
	return ipNet
}

func IPNetWithIPInIPv6Format(ipNetCIDRStr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(ipNetCIDRStr)
	ipNet.IP = ipNet.IP.To16()
	Expect(err).To(BeNil())
	return ipNet
}

func Mac(macStr string) net.HardwareAddr {
	mac, err := net.ParseMAC(macStr)
	Expect(err).To(BeNil())
	return mac
}

func IptypesIP6Address(address string) ip_types.IP6Address {
	addr, err := ip_types.ParseAddress(address)
	Expect(err).ToNot(HaveOccurred(), "failed to parse ip_types.IP6Addess from string %s", addr)
	return addr.Un.GetIP6()
}

func SidArray(addresses ...ip_types.IP6Address) (sids [16]ip_types.IP6Address) {
	copy(sids[:], addresses)
	return sids
}

func AddPaddingTo32Bytes(value []byte) []byte {
	result := [32]byte{}
	copy(result[:], value)
	return result[:]
}
