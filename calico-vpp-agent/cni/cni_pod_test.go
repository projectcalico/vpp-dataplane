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
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gs "github.com/onsi/gomega/gstruct"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	felixconfig "github.com/projectcalico/calico/felix/config"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/pod_interface"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/tests/mocks"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/config"
	"github.com/projectcalico/vpp-dataplane/multinet-monitor/networkAttachmentDefinition"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
		ipamStub  *mocks.IpamCacheStub
	)

	BeforeEach(func() {
		log = logrus.New()
		startVPP()
		vpp, _ = configureVPP(log)
		// setup connectivity server (functionality target of tests)
		if ipamStub == nil {
			ipamStub = mocks.NewIpamCacheStub()
		}
		// setup CNI server (functionality target of tests)
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		cniServer = cni.NewCNIServer(vpp, ipamStub, log.WithFields(logrus.Fields{"component": "cni"}))
		cniServer.SetFelixConfig(&felixconfig.Config{})
		cniServer.FetchBufferConfig()
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
					newPod := &cniproto.AddRequest{
						InterfaceName: interfaceName,
						Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
						ContainerIps:  []*cniproto.IPConfig{{Address: ipAddress + "/24"}},
						Workload: &cniproto.WorkloadIDs{
							Annotations: map[string]string{
								"cni.projectcalico.org/AllowedSourcePrefixes": "[\"172.16.104.7\", \"3.4.5.6\"]",
							},
						},
					}
					common.VppManagerInfo = &config.VppManagerInfo{}
					os.Setenv("NODENAME", ThisNodeName)
					os.Setenv("CALICOVPP_CONFIG_TEMPLATE", "sss")
					config.GetCalicoVppInterfaces().DefaultPodIfSpec = &config.InterfaceSpec{}
					err = config.LoadConfigSilent(log)
					if err != nil {
						log.Error(err)
					}
					config.GetCalicoVppFeatureGates().IPSecEnabled = &config.False
					config.GetCalicoVppDebug().GSOEnabled = &config.True
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
					ifSwIfIndex := assertTunInterfaceExistence(vpp, newPod)

					By("Checking correct IP address of interface tunnel at VPP's end")
					assertTunnelInterfaceIPAddress(vpp, ifSwIfIndex, ipAddress)

					By("Checking correct MTU for tunnel interface at VPP's end")
					assertTunnelInterfaceMTU(vpp, ifSwIfIndex)

					runInPod(newPod.Netns, func() {
						By("Checking tun interface on pod side")
						_, err := netlink.LinkByName(interfaceName)
						Expect(err).ToNot(HaveOccurred(), "can't find tun interface in pod")
					})

					By("Checking created pod RPF VRF")
					RPFVRF := assertRPFVRFExistence(vpp, interfaceName, newPod.Netns)

					By("Checking RPF routes are added")
					assertRPFRoutes(vpp, RPFVRF, ifSwIfIndex, ipAddress)
				})
			})

			Context("With additional memif interface configured", func() {
				BeforeEach(func() {
					config.GetCalicoVppFeatureGates().MemifEnabled = &config.True
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
					newPod := &cniproto.AddRequest{
						InterfaceName: interfaceName,
						Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
						ContainerIps:  []*cniproto.IPConfig{{Address: ipAddress + "/24"}},
						Workload: &cniproto.WorkloadIDs{
							Annotations: map[string]string{
								// needed just for setting up steering of traffic to default Tun/Tap and to secondary Memif
								cni.VppAnnotationPrefix + cni.MemifPortAnnotation: fmt.Sprintf("tcp:%d-%d,udp:%d-%d",
									memifTCPPortStart, memifTCPPortEnd, memifUDPPortStart, memifUDPPortEnd),
							},
						},
					}
					common.VppManagerInfo = &config.VppManagerInfo{}
					reply, err := cniServer.Add(context.Background(), newPod)
					Expect(err).ToNot(HaveOccurred(), "Pod addition failed")
					Expect(reply.Successful).To(BeTrue(),
						fmt.Sprintf("Pod addition failed due to: %s", reply.ErrorMessage))

					By("Checking existence of main interface tunnel to pod (at VPP's end)")
					ifSwIfIndex := assertTunInterfaceExistence(vpp, newPod)

					By("Checking main tunnel's tun interface for common interface attributes")
					assertTunnelInterfaceIPAddress(vpp, ifSwIfIndex, ipAddress)
					assertTunnelInterfaceMTU(vpp, ifSwIfIndex)

					runInPod(newPod.Netns, func() {
						By("Checking main tunnel's tun interface on pod side")
						_, err := netlink.LinkByName(interfaceName)
						Expect(err).ToNot(HaveOccurred(), "can't find main interface in pod")
					})

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
					// Note: queues are allocated only when a client is listening
					// Expect(memifs[0].QueueSize).To(Equal(config.GetCalicoVppInterfaces().DefaultPodIfSpec.RxQueueSize))
					//Note:Memif.NumRxQueues and Memif.NumTxQueues is not dumped by VPP binary API dump -> can't test it

					By("Checking secondary tunnel's memif socket file") // checking only VPP setting, not file socket presence
					socket, err := vpp.MemifsocketByID(memifs[0].SocketId)
					Expect(err).ToNot(HaveOccurred(), "failed to get memif socket")
					Expect(socket.SocketFilename).To(Equal(
						fmt.Sprintf("@netns:%s@vpp/memif-%s", newPod.Netns, newPod.InterfaceName)),
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
				var (
					networkDefinition *watchers.NetworkDefinition
					pubSubHandlerMock *mocks.PubSubHandlerMock
				)

				BeforeEach(func() {
					config.GetCalicoVppFeatureGates().MultinetEnabled = &config.True

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

					// setup PubSub handler to catch LocalPodAddressAdded events
					pubSubHandlerMock = mocks.NewPubSubHandlerMock(common.LocalPodAddressAdded)
					pubSubHandlerMock.Start()
				})

				// TODO test multinet(additional network for pod) with MEMIF interface

				Context("With default (TAP) interface configured for secondary(multinet) tunnel to pod", func() {
					It("should have properly configured both TAP interface tunnels to VPP", func() {
						const (
							ipAddress              = "1.2.3.44"      // main TAP tunnel (=not multinet)
							mainInterfaceName      = "mainInterface" // name must be <=16 characters long due to tap name size on pod linux side
							secondaryInterfaceName = "secInterface"  // name must be <=16 characters long due to tap name size on pod linux side
						)

						By("Getting Pod mock container's PID")
						containerPidOutput, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}",
							PodMockContainerName).Output()
						Expect(err).Should(BeNil(), "Failed to get pod mock container's PID string")
						containerPidStr := strings.ReplaceAll(string(containerPidOutput), "\n", "")

						By("Adding Pod to primary network using CNI server")
						newPodForPrimaryNetwork := &cniproto.AddRequest{
							InterfaceName: mainInterfaceName,
							Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
							ContainerIps:  []*cniproto.IPConfig{{Address: ipAddress + "/24"}},
							Workload:      &cniproto.WorkloadIDs{},
						}
						common.VppManagerInfo = &config.VppManagerInfo{}
						reply, err := cniServer.Add(context.Background(), newPodForPrimaryNetwork)
						Expect(err).ToNot(HaveOccurred(), "Pod addition to primary network failed")
						Expect(reply.Successful).To(BeTrue(),
							fmt.Sprintf("Pod addition to primary network failed due to: %s", reply.ErrorMessage))

						By("Adding Pod to secondary(multinet) network using CNI server")
						secondaryIPAddress := firstIPinIPRange(networkDefinition.Range).String()
						newPodForSecondaryNetwork := &cniproto.AddRequest{
							InterfaceName: secondaryInterfaceName,
							Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
							ContainerIps: []*cniproto.IPConfig{{
								Address: secondaryIPAddress + "/24",
							}},
							Workload: &cniproto.WorkloadIDs{},
							DataplaneOptions: map[string]string{
								dpoNetworkNameFieldName(): networkDefinition.Name,
							},
						}
						reply, err = cniServer.Add(context.Background(), newPodForSecondaryNetwork)
						Expect(err).ToNot(HaveOccurred(), "Pod addition to secondary network failed")
						Expect(reply.Successful).To(BeTrue(),
							fmt.Sprintf("Pod addition to secondary network failed due to: %s", reply.ErrorMessage))

						By("Checking existence of main tun interface tunnel to pod (at VPP's end)")
						mainSwIfIndex := assertTunInterfaceExistence(vpp, newPodForPrimaryNetwork)

						By("Checking main tunnel's tun interface for common interface attributes")
						assertTunnelInterfaceIPAddress(vpp, mainSwIfIndex, ipAddress)
						assertTunnelInterfaceMTU(vpp, mainSwIfIndex)

						By("Checking secondary tunnel's tun interface for existence")
						secondarySwIfIndex := assertTunInterfaceExistence(vpp, newPodForSecondaryNetwork)

						By("Checking secondary tunnel's tun interface for common interface attributes")
						assertTunnelInterfaceIPAddress(vpp, secondarySwIfIndex, secondaryIPAddress)
						assertTunnelInterfaceMTU(vpp, secondarySwIfIndex)

						runInPod(newPodForSecondaryNetwork.Netns, func() {
							By("Checking main tunnel's tun interface on pod side")
							_, err := netlink.LinkByName(mainInterfaceName)
							Expect(err).ToNot(HaveOccurred(), "can't find main interface in pod")

							By("Checking secondary tunnel's tun interface on pod side")
							secTunLink, err := netlink.LinkByName(secondaryInterfaceName)
							Expect(err).ToNot(HaveOccurred(), "can't find secondary(multinet) interface in pod")

							By("Checking multinet related routes on pod side")
							secTunLinkRoutes, err := netlink.RouteList(secTunLink, syscall.AF_INET) // Ipv4 routes only
							Expect(err).ToNot(HaveOccurred(), "can't get routes from pod")
							Expect(secTunLinkRoutes).To(ContainElements(
								gs.MatchFields(gs.IgnoreExtras, gs.Fields{
									"Dst": gs.PointTo(Equal(*ipNet(networkDefinition.Range))),
								}),
							), "can't find route in pod that steers all multinet network "+
								"traffic into multinet tunnel interface in pod")
						})

						By("checking pushing of LocalPodAddressAdded event for BGP pod network announcing")
						// Note: BGP is not tested here, only that event for it was sent
						Expect(pubSubHandlerMock.ReceivedEvents).To(ContainElements(
							gs.MatchFields(gs.IgnoreExtras, gs.Fields{
								"Type": Equal(common.LocalPodAddressAdded),
								"New": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
									"ContainerIP": gs.PointTo(Equal(*ipNetWithIPInIPv6Format(ipAddress + "/32"))),
								}),
							}),
							gs.MatchFields(gs.IgnoreExtras, gs.Fields{
								"Type": Equal(common.LocalPodAddressAdded),
								"New": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
									"ContainerIP": gs.PointTo(Equal(*ipNetWithIPInIPv6Format(secondaryIPAddress + "/32"))),
								}),
							}),
						))

						By("Checking default route from pod-specific VRF to multinet network-specific vrf")
						podVrf4ID, podVrf6ID, err := podVRFs(secondaryInterfaceName, newPodForSecondaryNetwork.Netns, vpp)
						Expect(err).ToNot(HaveOccurred(), "can't find pod-specific VRFs")
						for idx, ipFamily := range vpplink.IpFamilies {
							podVrfID := podVrf4ID
							zeroIPNet := &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.IPMask(net.IPv4zero.To4())}
							if ipFamily.IsIp6 {
								podVrfID = podVrf6ID
								zeroIPNet = &net.IPNet{IP: net.IPv6zero, Mask: net.IPMask(net.IPv6zero)}
							}
							routes, err := vpp.GetRoutes(podVrfID, ipFamily.IsIp6)
							Expect(err).ToNot(HaveOccurred(),
								fmt.Sprintf("can't get %s routes in pod-specific VRF", ipFamily.Str))
							Expect(routes).To(ContainElements(
								types.Route{
									Paths: []types.RoutePath{{
										Table:     networkDefinition.VRF.Tables[idx],
										SwIfIndex: types.InvalidID,
										Gw:        zeroIPNet.IP,
									}},
									Dst:   zeroIPNet,
									Table: podVrfID,
								},
							), "can't find default route from pod-specific VRF to multinet "+
								"network-specific vrf")
						}

						By("Checking steering route in multinet network VRF leading to pod " +
							"using multinet tunnel interface")
						// Note: should be checked for all container IPs of multinet, but we have only one
						multinetVRFID := networkDefinition.VRF.Tables[ipFamilyIndex(vpplink.IpFamilyV4)] // secondaryIPAddress is from IpFamilyV4
						routes, err := vpp.GetRoutes(multinetVRFID, false)
						Expect(err).ToNot(HaveOccurred(),
							"can't get ipv4 routes in multinet network-specific VRF")
						Expect(routes).To(ContainElements(
							types.Route{
								Dst: ipNet(secondaryIPAddress + "/32"),
								Paths: []types.RoutePath{{
									SwIfIndex: secondarySwIfIndex,
									Gw:        ipNet(secondaryIPAddress + "/32").IP,
								}},
								Table: multinetVRFID,
							},
						), "can't find steering route in multinet network VRF leading "+
							"to pod using multinet tunnel interface")
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

func assertTunInterfaceExistence(vpp *vpplink.VppLink, newPod *cniproto.AddRequest) uint32 {
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

// assertRPFVRFExistence checks that dedicated VRF for RPF is created for interface in VPP
func assertRPFVRFExistence(vpp *vpplink.VppLink, interfaceName string, netnsName string) uint32 {
	VRFs, err := vpp.ListVRFs()
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to retrieve list of VRFs in VPP")
	hbytes := sha512.Sum512([]byte(fmt.Sprintf("%s%s%s%s", "4", netnsName, interfaceName, "RPF")))
	h := base64.StdEncoding.EncodeToString(hbytes[:])[:storage.VrfTagHashLen]
	s := fmt.Sprintf("%s-%s-%s-%s", h, "4", interfaceName, filepath.Base(netnsName))
	vrfTag := storage.TruncateStr(s, storage.MaxApiTagLen)
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

// assertRPFRoutes checks that a route to the pod is added in the RPFVRF and to addresses allowed
// to be spoofed
func assertRPFRoutes(vpp *vpplink.VppLink, vrfID uint32, swifindex uint32, ipAddress string) {
	routes, err := vpp.GetRoutes(vrfID, false)
	Expect(err).ShouldNot(HaveOccurred(),
		"Failed to get routes from RPF VRF")
	Expect(routes).To(ContainElements(
		types.Route{
			Dst: ipNet(ipAddress + "/32"),
			Paths: []types.RoutePath{{
				SwIfIndex: swifindex,
				Gw:        ipNet(ipAddress + "/32").IP,
			}},
			Table: vrfID,
		},
		types.Route{
			Dst: ipNet("172.16.104.7" + "/32"),
			Paths: []types.RoutePath{{
				SwIfIndex: swifindex,
				Gw:        ipNet(ipAddress + "/32").IP,
			}},
			Table: vrfID,
		},
		types.Route{
			Dst: ipNet("3.4.5.6" + "/32"),
			Paths: []types.RoutePath{{
				SwIfIndex: swifindex,
				Gw:        ipNet(ipAddress + "/32").IP,
			}},
			Table: vrfID,
		},
	), "Cannot find route to pod in RPF VRF %s", ipAddress)

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

// runInPod runs runner function in provided pod network namespace. This is the same as running
// networking commands inside pod.
func runInPod(podNetNS string, runner func()) {
	err := ns.WithNetNSPath(podNetNS, func(hostNS ns.NetNS) error {
		defer GinkgoRecover() // running in different goroutine -> needed for failed assertion retrieval
		runner()
		return nil
	})
	Expect(err).Should(BeNil(), "Failed to runInPod")
}

// dpoNetworkNameFieldName extracts JSON field name for NetworkName used in cniproto.AddRequest.DataplaneOptions
func dpoNetworkNameFieldName() string {
	netNameField, found := reflect.TypeOf(networkAttachmentDefinition.NetConf{}.DpOptions).FieldByName("NetName")
	Expect(found).To(BeTrue(),
		"can't find network name field in NetworkAttachmentDefinition. Did that structure changed?")
	jsonStr, isSet := netNameField.Tag.Lookup("json")
	Expect(isSet).To(BeTrue(), "can't find json name for network name field in NetworkAttachmentDefinition")
	return strings.Split(jsonStr, ",")[0]
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

// firstIPinIPRange computes first usable IPv4 address from the given subnet. The subnet definition IP address
// (ending with zero bits) is not considered as usable IPv4 address as it can have special meaning in certain situations.
func firstIPinIPRange(ipRangeCIDR string) net.IP {
	ip, _, err := net.ParseCIDR(ipRangeCIDR)
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("can't parse range subnet string %s as CIDR", ipRangeCIDR))
	ip = ip.To4() // expecting IPv4 address
	ip[3]++       // incrementing last IP address byte to get the first usable IP address in subnet range (subnet x.y.z.0 -> first ip address x.y.z.1)
	return ip
}

// podVRFs gets ids of IPv4 and IPv6 pod-specific VRFs from VPP
func podVRFs(podInterface, podNetNSName string, vpp *vpplink.VppLink) (vrf4ID, vrf6ID uint32, err error) {
	vrfs, err := vpp.ListVRFs()
	Expect(err).ToNot(HaveOccurred(), "error listing VRFs to find all pod VRFs")

	podSpec := storage.LocalPodSpec{
		InterfaceName: podInterface,
		NetnsName:     podNetNSName,
		V4VrfId:       types.InvalidID,
		V6VrfId:       types.InvalidID,
	}
	for _, vrf := range vrfs {
		for _, ipFamily := range vpplink.IpFamilies {
			if vrf.Name == podSpec.GetVrfTag(ipFamily, "") {
				podSpec.SetVrfId(vrf.VrfID, ipFamily)
			}
		}
		if podSpec.V4VrfId != types.InvalidID && podSpec.V6VrfId != types.InvalidID {
			return podSpec.V4VrfId, podSpec.V6VrfId, nil
		}
	}

	if (podSpec.V4VrfId != types.InvalidID) != (podSpec.V6VrfId != types.InvalidID) {
		return podSpec.V4VrfId, podSpec.V6VrfId,
			fmt.Errorf("partial VRF state v4=%d v6=%d key=%s", podSpec.V4VrfId, podSpec.V6VrfId, podSpec.Key())
	}

	return podSpec.V4VrfId, podSpec.V6VrfId, fmt.Errorf("not VRFs state (key=%s)", podSpec.Key())
}

func ipFamilyIndex(ipFamily vpplink.IpFamily) int {
	for idx, family := range vpplink.IpFamilies {
		if family == ipFamily {
			return idx
		}
	}
	return math.MaxInt
}
