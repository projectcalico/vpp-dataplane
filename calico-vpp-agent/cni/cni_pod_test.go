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
	"fmt"
	"net"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/pod_interface"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	agentConf "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

const (
	// PodMockContainerName is used container name for pod container mock
	PodMockContainerName = "cni-tests-pod-mock"
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
			Context("With default configuration", func() {
				It("should have properly configured TUN interface tunnel to VPP", func() {
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
					ifSwIfIndex := assertMainTunInterfaceExistence(vpp, newPod)

					By("Checking correct IP address of interface tunnel at VPP's end")
					assertTunnelInterfaceIPAddress(vpp, ifSwIfIndex, ipAddress)

					By("Checking correct MTU for tunnel interface at VPP's end")
					assertTunnelInterfaceMTU(vpp, ifSwIfIndex)
				})
			})

			Context("With additional memif interface configured", func() {
				BeforeEach(func() {
					agentConf.MemifEnabled = true
					agentConf.TapRxQueueSize = 0 // must be 0 as main TUN interface creation will fail
				})

				// TODO test also use case with that creates memif-dummy interface in pod (dummy interface is
				//  just holder for all configuration of memif interface that should be created with exposed memif socket)

				It("should have properly configured default TUN interface tunnel to VPP and "+
					"exposed Memif socket to Memif interface in VPP", func() {
					const (
						ipAddress         = "1.2.3.44"
						interfaceName     = "newInterface"
						memifTCPPortStart = 2222
						memifTCPPortEnd   = 33333
						memifUDPPortStart = 4444
						memifUDPPortEnd   = 55555
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
						Workload: &proto.WorkloadIDs{
							Annotations: map[string]string{
								// needed just for setting up steering of traffic to default Tun/Tap and to secondary Memif
								cni.VppAnnotationPrefix + cni.MemifPortAnnotation: fmt.Sprintf("tcp:%d-%d,udp:%d-%d",
									memifTCPPortStart, memifTCPPortEnd, memifUDPPortStart, memifUDPPortEnd),
								cni.VppAnnotationPrefix + cni.TunTapPortAnnotation: "default",
							},
						},
					}
					reply, err := cniServer.Add(context.Background(), newPod)
					Expect(err).ToNot(HaveOccurred(), "Pod addition failed")
					Expect(reply.Successful).To(BeTrue(),
						fmt.Sprintf("Pod addition failed due to: %s", reply.ErrorMessage))

					By("Checking existence of main interface tunnel to pod (at VPP's end)")
					ifSwIfIndex := assertMainTunInterfaceExistence(vpp, newPod)

					By("Checking main tunnel's tun interface for common interface attributes")
					assertTunnelInterfaceIPAddress(vpp, ifSwIfIndex, ipAddress)
					assertTunnelInterfaceMTU(vpp, ifSwIfIndex)

					By("Checking secondary tunnel's memif interface for existence")
					memifSwIfIndex, err := vpp.SearchInterfaceWithTag(
						interfaceTagForLocalMemifTunnel(newPod.InterfaceName, newPod.Netns))
					Expect(err).ShouldNot(HaveOccurred(), "Failed to get memif interface at VPP's end")

					By("Checking secondary tunnel's memif interface for common interface attributes")
					assertTunnelInterfaceIPAddress(vpp, memifSwIfIndex, ipAddress)
					assertTunnelInterfaceMTU(vpp, memifSwIfIndex)
					assertInterfaceGSO(memifSwIfIndex, "secondary tunnel's memif interface", vpp)

					By("Checking secondary tunnel's memif interface for memif attributes")
					memifs, err := vpp.ListMemifInterfaces()
					Expect(err).ToNot(HaveOccurred(), "failed to get memif interfaces")
					Expect(memifs).ToNot(BeEmpty(), "no memif interfaces retrieved")
					Expect(memifs[0].Role).To(Equal(types.MemifMaster))
					Expect(memifs[0].Mode).To(Equal(types.MemifModeEthernet))
					Expect(memifs[0].Flags&types.MemifAdminUp > 0).To(BeTrue())
					Expect(memifs[0].QueueSize).To(Equal(agentConf.TapRxQueueSize))
					//Note:Memif.NumRxQueues and Memif.NumTxQueues is not dumped by VPP binary API dump -> can't test it

					By("Checking secondary tunnel's memif socket file") // checking only VPP setting, not file socket presence
					socket, err := vpp.MemifsocketByID(memifs[0].SocketId)
					Expect(err).ToNot(HaveOccurred(), "failed to get memif socket")
					Expect(socket.SocketFilename).To(Equal(
						fmt.Sprintf("@netns:%s%s-%s", newPod.Netns, agentConf.MemifSocketName, newPod.InterfaceName)),
						"memif socket file is not configured correctly")

					By("Checking PBL (packet punting) to redirect some traffic into memif (secondary interface)")
					pblClientStr, err := vpp.RunCli("sh pbl client")
					Expect(err).ToNot(HaveOccurred(), "failed to get PBL configuration")
					pblClientStr = strings.ToLower(pblClientStr)
					Expect(pblClientStr).To(ContainSubstring(fmt.Sprintf("pbl-client: %s clone:1", ipAddress)),
						"PBL doesn't clone the main interface traffic")
					Expect(strings.Count(pblClientStr, "pbl-client")).To(Equal(2),
						"got some missing pbl clients (one for main interface and one for memif)")
					Expect(pblClientStr).To(ContainSubstring(
						fmt.Sprintf("tcp ports: %d-%d", memifTCPPortStart, memifTCPPortEnd)),
						"TCP port range is not correctly configured for memif interface")
					Expect(pblClientStr).To(ContainSubstring(
						fmt.Sprintf("udp ports: %d-%d", memifUDPPortStart, memifUDPPortEnd)),
						"UDP port range is not correctly configured for memif interface")
				})

			})

			Context("With MultiNet configuration (and multinet VRF and loopback already configured)", func() {
				var networkDefinition *watchers.NetworkDefinition

				BeforeEach(func() {
					agentConf.MultinetEnabled = true

					// Setup test prerequisite (per-multinet-network VRF and loopback interface)")
					// (this is normally done by watchers.NetWatcher.CreateVRFsForNet(...))
					loopbackSwIfIndex, err := vpp.CreateLoopback(&common.ContainerSideMacAddress)
					Expect(err).ToNot(HaveOccurred(), "error creating loopback for multinet network")
					var tables [2]uint32
					networkName := "myFirstMultinetNetwork"
					for idx, ipFamily := range vpplink.IpFamilies {
						vrfName := fmt.Sprintf("pod-%s-table-%s", networkName, ipFamily.Str)
						vrfId, err := vpp.AllocateVRF(ipFamily.IsIp6, vrfName)
						Expect(err).ToNot(HaveOccurred(),
							fmt.Sprintf("can't create VRF table requirement for IP family %s", ipFamily.Str))
						tables[idx] = vrfId
					}
					// NetworkDefinition CRD information caught by NetWatcher and send with additional information
					// (VRF and loopback created by watcher) to the cni server as common.NetAdded CalicoVPPEvent
					networkDefinition = &watchers.NetworkDefinition{
						VRF:               watchers.VRF{Tables: tables},
						Vni:               uint32(0), // important only for VXLAN tunnel going out of node
						Name:              networkName,
						LoopbackSwIfIndex: loopbackSwIfIndex,
						Range:             "10.1.1.0/24", // IP range for secondary network defined by multinet
					}
					cniServer.ForceAddingNetworkDefinition(networkDefinition)
				})

				// TODO test multinet(additional network for pod) with MEMIF interface

				Context("With default (TAP) interface configured for secondary(multinet) tunnel to pod", func() {
					It("should have properly configured both TAP interface tunnels to VPP", func() {
						const (
							ipAddress              = "1.2.3.44" // main TAP tunnel (=not multinet)
							mainInterfaceName      = "mainInterface"
							secondaryInterfaceName = "secondaryInterface"
						)

						By("Getting Pod mock container's PID")
						containerPidOutput, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}",
							PodMockContainerName).Output()
						Expect(err).Should(BeNil(), "Failed to get pod mock container's PID string")
						containerPidStr := strings.ReplaceAll(string(containerPidOutput), "\n", "")

						By("Adding Pod to primary network using CNI server")
						newPodForPrimaryNetwork := &proto.AddRequest{
							InterfaceName: mainInterfaceName,
							Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
							ContainerIps:  []*proto.IPConfig{{Address: ipAddress + "/24"}},
							Workload:      &proto.WorkloadIDs{},
						}
						reply, err := cniServer.Add(context.Background(), newPodForPrimaryNetwork)
						Expect(err).ToNot(HaveOccurred(), "Pod addition to primary network failed")
						Expect(reply.Successful).To(BeTrue(),
							fmt.Sprintf("Pod addition to primary network failed due to: %s", reply.ErrorMessage))

						By("Adding Pod to secondary(multinet) network using CNI server")
						newPodForSecondaryNetwork := &proto.AddRequest{
							InterfaceName: secondaryInterfaceName,
							Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
							ContainerIps: []*proto.IPConfig{{
								Address: firstIPinIPRange(networkDefinition.Range).String() + "/24",
							}},
							Workload: &proto.WorkloadIDs{},
						}
						reply, err = cniServer.Add(context.Background(), newPodForSecondaryNetwork)
						Expect(err).ToNot(HaveOccurred(), "Pod addition to secondary network failed")
						Expect(reply.Successful).To(BeTrue(),
							fmt.Sprintf("Pod addition to secondary network failed due to: %s", reply.ErrorMessage))

						// TODO check 2 TAP interfaces that they exists and are well configured
						// TODO networkdefinition -> default route from pod vrf to global pod vrf/multinet pod vrf
						//  -> route from global pod vrf/multinet pod vrf to pod interface
						//  -> s.networkDefinitions[podSpec.NetworkName].Range to podSpec.Routes
						//  -> route settings in pod
						//  -> bgp pod announcing/withdraw (common.LocalPodAddressAdded + common.LocalPodAddressDeleted)
					})
				})
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

func assertMainTunInterfaceExistence(vpp *vpplink.VppLink, newPod *proto.AddRequest) uint32 {
	ifSwIfIndex, err := vpp.SearchInterfaceWithTag(
		interfaceTagForLocalTunTunnel(newPod.InterfaceName, newPod.Netns))
	Expect(err).ShouldNot(HaveOccurred(), "Failed to get interface at VPP's end")
	Expect(ifSwIfIndex).ToNot(Equal(vpplink.INVALID_SW_IF_INDEX),
		"No interface at VPP's end is found")
	Expect(ifSwIfIndex).NotTo(BeZero(), "No interface at VPP's end is found")
	return ifSwIfIndex
}

func assertTunnelInterfaceIPAddress(vpp *vpplink.VppLink, ifSwIfIndex uint32, expectedIPAddress string) {
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

func assertTunnelInterfaceMTU(vpp *vpplink.VppLink, ifSwIfIndex uint32) {
	details, err := vpp.GetInterfaceDetails(ifSwIfIndex)
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to retrieve interface details of VPP's end of interface tunnel")
	Expect(int(details.Mtu[0])).To(Equal(vpplink.MAX_MTU),
		"VPP's end of interface tunnel has not correctly configured MTU")
}

// assertInterfaceGSOCNat check whether the given interface has properly set the GSO and CNAT attributes
func assertInterfaceGSO(swIfIndex uint32, interfaceDescriptiveName string, vpp *vpplink.VppLink) {
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
	return interfaceTagForLocalTunnel(pod_interface.NewTunTapPodInterfaceDriver(nil, nil).Name,
		interfaceName, netns)
}

// interfaceTagForLocalMemifTunnel constructs the tag for the VPP side of the memif tunnel the same way as cni server
func interfaceTagForLocalMemifTunnel(interfaceName, netns string) string {
	return interfaceTagForLocalTunnel(pod_interface.NewMemifPodInterfaceDriver(nil, nil).Name,
		interfaceName, netns)
}

// interfaceTagForLocalTunnel constructs the tag for the VPP side of the local tunnel the same way as cni server
func interfaceTagForLocalTunnel(prefix, interfaceName, netns string) string {
	return (&storage.LocalPodSpec{
		NetnsName:     netns,
		InterfaceName: interfaceName,
	}).GetInterfaceTag(prefix)
}

func firstIPinIPRange(ipRangeCIDR string) net.IP {
	ip, _, err := net.ParseCIDR(ipRangeCIDR)
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("can't parse range subnet string %s as CIDR", ipRangeCIDR))
	ip = ip.To4()
	ip[3]++
	return ip
}
