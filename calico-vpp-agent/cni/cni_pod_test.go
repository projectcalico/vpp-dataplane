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
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gs "github.com/onsi/gomega/gstruct"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	felixconfig "github.com/projectcalico/calico/felix/config"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	test "github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common_tests"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/tests/mocks"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"

	gomemif "go.fd.io/govpp/extras/gomemif/memif"
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
		test.StartVPP()
		vpp, _ = test.ConfigureVPP(log)
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
			test.CreatePod()
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
					ifSwIfIndex := test.AssertTunInterfaceExistence(vpp, newPod)

					By("Checking correct IP address of interface tunnel at VPP's end")
					test.AssertTunnelInterfaceIPAddress(vpp, ifSwIfIndex, ipAddress)

					By("Checking correct MTU for tunnel interface at VPP's end")
					test.AssertTunnelInterfaceMTU(vpp, ifSwIfIndex)

					test.RunInPod(newPod.Netns, func() {
						By("Checking tun interface on pod side")
						_, err := netlink.LinkByName(interfaceName)
						Expect(err).ToNot(HaveOccurred(), "can't find tun interface in pod")
					})

					By("Checking created pod RPF VRF")
					RPFVRF := test.AssertRPFVRFExistence(vpp, interfaceName, newPod.Netns)

					By("Checking RPF routes are added")
					test.AssertRPFRoutes(vpp, RPFVRF, ifSwIfIndex, ipAddress)
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
					ifSwIfIndex := test.AssertTunInterfaceExistence(vpp, newPod)

					By("Checking main tunnel's tun interface for common interface attributes")
					test.AssertTunnelInterfaceIPAddress(vpp, ifSwIfIndex, ipAddress)
					test.AssertTunnelInterfaceMTU(vpp, ifSwIfIndex)

					test.RunInPod(newPod.Netns, func() {
						By("Checking main tunnel's tun interface on pod side")
						_, err := netlink.LinkByName(interfaceName)
						Expect(err).ToNot(HaveOccurred(), "can't find main interface in pod")
					})

					By("Checking secondary tunnel's memif interface for existence")
					memifSwIfIndex, err := vpp.SearchInterfaceWithTag(
						test.InterfaceTagForLocalMemifTunnel(newPod.InterfaceName, newPod.Netns))
					Expect(err).ShouldNot(HaveOccurred(), "Failed to get memif interface at VPP's end")

					By("Checking secondary tunnel's memif interface for common interface attributes")
					test.AssertTunnelInterfaceIPAddress(vpp, memifSwIfIndex, ipAddress)
					test.AssertTunnelInterfaceMTU(vpp, memifSwIfIndex)
					test.AssertInterfaceGSO(memifSwIfIndex, "secondary tunnel's memif interface", vpp)

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
						fmt.Sprintf("abstract:vpp/memif-%s,netns_name=%s", newPod.InterfaceName, newPod.Netns)),
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

					By("Checking socket creation")
					memif_socket, err := gomemif.NewSocket("gomemif_example", "@vpp/memif-newInterface")
					Expect(err).ToNot(HaveOccurred())

					By("Checking slave connection to master")
					memifErrChan := make(chan error)
					quitChan := make(chan int)
					// Start master polling
					go func() {
						for {
							select {
							case <-quitChan:
								return
							default:
								memif_socket.StartPolling(memifErrChan)
								time.Sleep(100 * time.Millisecond)
							}
						}
					}()

					sockChannel := make(chan *gomemif.Interface, 1)

					slave := func() error {
						args := &gomemif.Arguments{
							IsMaster:         false,
							Name:             "memif",
							ConnectedFunc:    func(i *gomemif.Interface) error { return nil },
							DisconnectedFunc: func(i *gomemif.Interface) error { return nil },
						}

						i, err := memif_socket.NewInterface(args)
						if err != nil {
							return err
						}

						retry := 5
						for !i.IsConnecting() {
							err = i.RequestConnection()
							if err != nil {
								retry--
							}
							if retry == 0 {
								sockChannel <- nil
								return err
							}
							time.Sleep(100 * time.Millisecond)
						}
						sockChannel <- i
						return nil
					}
					// Create slave socket in container net space
					err = cni.NetNsExec("pid:"+containerPidStr, slave)
					Expect(err).ToNot(HaveOccurred())
					i := <-sockChannel

					By("Sending a ARP request")
					srcMac := net.HardwareAddr{0x01, 0x66, 0x38, 0xa1, 0x12, 0x46}
					srcIp := net.IPv4(1, 2, 3, 4)
					dstIp := net.IPv4(1, 2, 3, 5)

					arp, err := cni.NewArpRequestPacket(srcMac, srcIp, dstIp)
					Expect(err).ToNot(HaveOccurred())
					txq, err := i.GetTxQueue(0)
					Expect(err).ToNot(HaveOccurred())

					bytesWritten := txq.WritePacket(arp)
					Expect(bytesWritten).To(Equal(len(arp)))
					quitChan <- 1
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
					_, err := vpp.CreateLoopback(common.ContainerSideMacAddress)
					Expect(err).ToNot(HaveOccurred(), "error creating loopback for multinet network")
					var tables [2]uint32
					networkName := "myFirstMultinetNetwork"
					for idx, ipFamily := range vpplink.IpFamilies {
						vrfName := fmt.Sprintf("%s-table-%s", networkName, ipFamily.Str)
						vrfId, err := vpp.AllocateVRF(ipFamily.IsIp6, vrfName)
						Expect(err).ToNot(HaveOccurred(),
							fmt.Sprintf("can't create VRF table requirement for IP family %s", ipFamily.Str))
						tables[idx] = vrfId
					}
					var podTables [2]uint32
					for idx, ipFamily := range vpplink.IpFamilies {
						vrfName := fmt.Sprintf("pod-%s-table-%s", networkName, ipFamily.Str)
						vrfId, err := vpp.AllocateVRF(ipFamily.IsIp6, vrfName)
						Expect(err).ToNot(HaveOccurred(),
							fmt.Sprintf("can't create VRF table requirement for IP family %s", ipFamily.Str))
						podTables[idx] = vrfId
						err = vpp.AddDefaultRouteViaTable(podTables[idx], tables[idx], ipFamily.IsIp6)
						Expect(err).ToNot(HaveOccurred(), "can't add default route")
					}
					// NetworkDefinition CRD information caught by NetWatcher and send with additional information
					// (VRF and loopback created by watcher) to the cni server as common.NetAdded CalicoVPPEvent
					networkDefinition = &watchers.NetworkDefinition{
						VRF:    watchers.VRF{Tables: tables},
						PodVRF: watchers.VRF{Tables: podTables},
						Vni:    uint32(0), // important only for VXLAN tunnel going out of node
						Name:   networkName,
						Range:  "10.1.1.0/24", // IP range for secondary network defined by multinet
					}
					cniServer.ForceAddingNetworkDefinition(networkDefinition)

					// setup PubSub handler to catch LocalPodAddressAdded events
					pubSubHandlerMock = mocks.NewPubSubHandlerMock(common.LocalPodAddressAdded)
					pubSubHandlerMock.Start()
				})

				Context("With default memif interface configured for secondary(multinet) tunnel to pod", func() {
					BeforeEach(func() {
						config.GetCalicoVppFeatureGates().MemifEnabled = &config.True
					})
					It("should have properly configured both interfaces tunnels to VPP", func() {
						const (
							ipAddress              = "1.2.3.44"      // main TAP tunnel (=not multinet)
							mainInterfaceName      = "mainInterface" // name must be <=16 characters long due to tap name size on pod linux side
							secondaryInterfaceName = "memif2nd"      // name must be <=16 characters long due to tap name size on pod linux side
							memifTCPPortStart      = 2222
							memifTCPPortEnd        = 33333
							memifUDPPortStart      = 4444
							memifUDPPortEnd        = 55555
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
						secondaryIPAddress := test.FirstIPinIPRange(networkDefinition.Range).String()
						newPodForSecondaryNetwork := &cniproto.AddRequest{
							InterfaceName: secondaryInterfaceName,
							Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
							ContainerIps: []*cniproto.IPConfig{{
								Address: secondaryIPAddress + "/24",
							}},
							//Workload: &cniproto.WorkloadIDs{},
							DataplaneOptions: map[string]string{
								test.DpoNetworkNameFieldName(): networkDefinition.Name,
							},
							Workload: &cniproto.WorkloadIDs{
								Annotations: map[string]string{
									// needed just for setting up steering of traffic to default Tun/Tap and to secondary Memif
									cni.VppAnnotationPrefix + cni.MemifPortAnnotation: fmt.Sprintf("tcp:%d-%d,udp:%d-%d",
										memifTCPPortStart, memifTCPPortEnd, memifUDPPortStart, memifUDPPortEnd),
								},
							},
						}
						reply, err = cniServer.Add(context.Background(), newPodForSecondaryNetwork)
						Expect(err).ToNot(HaveOccurred(), "Pod addition to secondary network failed")
						Expect(reply.Successful).To(BeTrue(),
							fmt.Sprintf("Pod addition to secondary network failed due to: %s", reply.ErrorMessage))

						By("Checking existence of main tun interface tunnel to pod (at VPP's end)")
						mainSwIfIndex := test.AssertTunInterfaceExistence(vpp, newPodForPrimaryNetwork)

						By("Checking main tunnel's tun interface for common interface attributes")
						test.AssertTunnelInterfaceIPAddress(vpp, mainSwIfIndex, ipAddress)
						test.AssertTunnelInterfaceMTU(vpp, mainSwIfIndex)

						//By("Checking secondary tunnel's tun interface for existence")
						//secondarySwIfIndex := test.AssertTunInterfaceExistence(vpp, newPodForSecondaryNetwork)
						By("Checking secondary tunnel's memif interface for existence")
						memifSwIfIndex, err := vpp.SearchInterfaceWithTag(
							test.InterfaceTagForLocalMemifTunnel(newPodForSecondaryNetwork.InterfaceName, newPodForSecondaryNetwork.Netns))
						Expect(err).ShouldNot(HaveOccurred(), "Failed to get memif interface at VPP's end")

						By("Checking secondary tunnel's memif interface for common interface attributes")
						test.AssertTunnelInterfaceIPAddress(vpp, memifSwIfIndex, secondaryIPAddress)
						test.AssertTunnelInterfaceMTU(vpp, memifSwIfIndex)
						test.AssertInterfaceGSO(memifSwIfIndex, "secondary tunnel's memif interface", vpp)

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
							fmt.Sprintf("abstract:%s,netns_name=%s", newPodForSecondaryNetwork.InterfaceName, newPodForSecondaryNetwork.Netns)),
							"memif socket file is not configured correctly")

						test.RunInPod(newPodForSecondaryNetwork.Netns, func() {
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
									"Dst": gs.PointTo(Equal(*test.IpNet(networkDefinition.Range))),
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
									"ContainerIP": gs.PointTo(Equal(*test.IpNetWithIPInIPv6Format(ipAddress + "/32"))),
								}),
							}),
							gs.MatchFields(gs.IgnoreExtras, gs.Fields{
								"Type": Equal(common.LocalPodAddressAdded),
								"New": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
									"ContainerIP": gs.PointTo(Equal(*test.IpNetWithIPInIPv6Format(secondaryIPAddress + "/32"))),
								}),
							}),
						))

						By("Checking default route from pod-specific VRF to multinet network-specific pod-vrf")
						podVrf4ID, podVrf6ID, err := test.PodVRFs(secondaryInterfaceName, newPodForSecondaryNetwork.Netns, vpp)
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
										Table:     networkDefinition.PodVRF.Tables[idx],
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
						multinetVRFID := networkDefinition.VRF.Tables[test.IpFamilyIndex(vpplink.IpFamilyV4)] // secondaryIPAddress is from IpFamilyV4
						routes, err := vpp.GetRoutes(multinetVRFID, false)
						Expect(err).ToNot(HaveOccurred(),
							"can't get ipv4 routes in multinet network-specific VRF")
						Expect(routes).To(ContainElements(
							types.Route{
								Dst: test.IpNet(secondaryIPAddress + "/32"),
								Paths: []types.RoutePath{{
									SwIfIndex: memifSwIfIndex,
									Gw:        test.IpNet(secondaryIPAddress + "/32").IP,
								}},
								Table: multinetVRFID,
							},
						), "can't find steering route in multinet network VRF leading "+
							"to pod using multinet tunnel interface")

						By("Checking socket creation")
						memif_socket, err := gomemif.NewSocket("gomemif_example", "@"+secondaryInterfaceName)
						Expect(err).ToNot(HaveOccurred())

						By("Checking slave connection to master")
						memifErrChan := make(chan error)
						quitChan := make(chan int)
						// Start master polling
						go func() {
							for {
								select {
								case <-quitChan:
									return
								default:
									memif_socket.StartPolling(memifErrChan)
									time.Sleep(100 * time.Millisecond)
								}
							}
						}()

						sockChannel := make(chan *gomemif.Interface, 1)

						slave := func() error {
							args := &gomemif.Arguments{
								IsMaster:         false,
								Name:             "memif",
								ConnectedFunc:    func(i *gomemif.Interface) error { return nil },
								DisconnectedFunc: func(i *gomemif.Interface) error { return nil },
							}

							i, err := memif_socket.NewInterface(args)
							if err != nil {
								return err
							}

							retry := 5
							for !i.IsConnecting() {
								err = i.RequestConnection()
								if err != nil {
									retry--
								}
								if retry == 0 {
									sockChannel <- nil
									return err
								}
								time.Sleep(100 * time.Millisecond)
							}
							sockChannel <- i
							return nil
						}
						// Create slave socket in container net space
						err = cni.NetNsExec("pid:"+containerPidStr, slave)
						Expect(err).ToNot(HaveOccurred())
						i := <-sockChannel
						Expect(i).ToNot(BeNil())

						By("Sending a ARP request")
						srcMac := net.HardwareAddr{0x01, 0x66, 0x38, 0xa1, 0x12, 0x46}
						srcIp := net.IPv4(1, 2, 3, 4)
						dstIp := net.IPv4(1, 2, 3, 5)

						arp, err := cni.NewArpRequestPacket(srcMac, srcIp, dstIp)
						Expect(err).ToNot(HaveOccurred())
						txq, err := i.GetTxQueue(0)
						Expect(err).ToNot(HaveOccurred())

						bytesWritten := txq.WritePacket(arp)
						Expect(bytesWritten).To(Equal(len(arp)))
						quitChan <- 1
					})
				})
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
						secondaryIPAddress := test.FirstIPinIPRange(networkDefinition.Range).String()
						newPodForSecondaryNetwork := &cniproto.AddRequest{
							InterfaceName: secondaryInterfaceName,
							Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
							ContainerIps: []*cniproto.IPConfig{{
								Address: secondaryIPAddress + "/24",
							}},
							Workload: &cniproto.WorkloadIDs{},
							DataplaneOptions: map[string]string{
								test.DpoNetworkNameFieldName(): networkDefinition.Name,
							},
						}
						reply, err = cniServer.Add(context.Background(), newPodForSecondaryNetwork)
						Expect(err).ToNot(HaveOccurred(), "Pod addition to secondary network failed")
						Expect(reply.Successful).To(BeTrue(),
							fmt.Sprintf("Pod addition to secondary network failed due to: %s", reply.ErrorMessage))

						By("Checking existence of main tun interface tunnel to pod (at VPP's end)")
						mainSwIfIndex := test.AssertTunInterfaceExistence(vpp, newPodForPrimaryNetwork)

						By("Checking main tunnel's tun interface for common interface attributes")
						test.AssertTunnelInterfaceIPAddress(vpp, mainSwIfIndex, ipAddress)
						test.AssertTunnelInterfaceMTU(vpp, mainSwIfIndex)

						By("Checking secondary tunnel's tun interface for existence")
						secondarySwIfIndex := test.AssertTunInterfaceExistence(vpp, newPodForSecondaryNetwork)

						By("Checking secondary tunnel's tun interface for common interface attributes")
						test.AssertTunnelInterfaceIPAddress(vpp, secondarySwIfIndex, secondaryIPAddress)
						test.AssertTunnelInterfaceMTU(vpp, secondarySwIfIndex)

						test.RunInPod(newPodForSecondaryNetwork.Netns, func() {
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
									"Dst": gs.PointTo(Equal(*test.IpNet(networkDefinition.Range))),
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
									"ContainerIP": gs.PointTo(Equal(*test.IpNetWithIPInIPv6Format(ipAddress + "/32"))),
								}),
							}),
							gs.MatchFields(gs.IgnoreExtras, gs.Fields{
								"Type": Equal(common.LocalPodAddressAdded),
								"New": gs.MatchFields(gs.IgnoreExtras, gs.Fields{
									"ContainerIP": gs.PointTo(Equal(*test.IpNetWithIPInIPv6Format(secondaryIPAddress + "/32"))),
								}),
							}),
						))

						By("Checking default route from pod-specific VRF to multinet network-specific vrf")
						podVrf4ID, podVrf6ID, err := test.PodVRFs(secondaryInterfaceName, newPodForSecondaryNetwork.Netns, vpp)
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
										Table:     networkDefinition.PodVRF.Tables[idx],
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
						multinetVRFID := networkDefinition.VRF.Tables[test.IpFamilyIndex(vpplink.IpFamilyV4)] // secondaryIPAddress is from IpFamilyV4
						routes, err := vpp.GetRoutes(multinetVRFID, false)
						Expect(err).ToNot(HaveOccurred(),
							"can't get ipv4 routes in multinet network-specific VRF")
						Expect(routes).To(ContainElements(
							types.Route{
								Dst: test.IpNet(secondaryIPAddress + "/32"),
								Paths: []types.RoutePath{{
									SwIfIndex: secondarySwIfIndex,
									Gw:        test.IpNet(secondaryIPAddress + "/32").IP,
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
			test.TeardownPod()
		})
	})

	AfterEach(func() {
		test.TeardownVPP()
	})
})
