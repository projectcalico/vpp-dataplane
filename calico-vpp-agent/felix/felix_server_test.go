package felix

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/testutils"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"

	"github.com/sirupsen/logrus"
)

// Names of integration tests arguments
const (
	VppImageArgName           = "VPP_IMAGE"
	VppBinaryArgName          = "VPP_BINARY"
	VppContainerExtraArgsName = "VPP_CONTAINER_EXTRA_ARGS"
)

// TestFelixIntegration runs all the ginkgo integration test inside felix package
func TestFelixIntegration(t *testing.T) {
	// skip test if test run is not integration test run (prevent accidental run of integration tests using go test ./...)
	_, isIntegrationTestRun := os.LookupEnv(VppImageArgName)
	if !isIntegrationTestRun {
		t.Skip("skipping felix integration tests (set INTEGRATION_TEST env variable to run these tests)")
	}

	// integrate gomega and ginkgo -> register all Felix integration tests
	RegisterFailHandler(Fail)
	RunSpecs(t, "Felix Integration Suite")
}

var _ = BeforeSuite(func() {
	// extract common input for CNI integration tests
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

})

var _ = Describe("Felix functionality", func() {
	var (
		log         *logrus.Logger
		vpp         *vpplink.VppLink
		felixServer *Server
		ipv4        net.IP
		ipv6        net.IP
	)

	BeforeEach(func() {
		log = logrus.New()
		// Set unique container name for Felix tests
		testutils.VPPContainerName = "felix-tests-vpp"
		testutils.StartVPP()
		vpp, _ = testutils.ConfigureVPP(log)
		// add interface to mock the tap0 because felix server needs it
		CreateLoopbackAndTaggingItAsMain(vpp, log)
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		var err error
		felixServer, err = NewFelixServer(vpp, log.WithFields(logrus.Fields{"component": "policy"}))
		if err != nil {
			log.Fatalf("Failed to create felix server %s", err)
		}
		ipv4, _, _ = net.ParseCIDR("1.1.1.1/32")
		ipv6, _, _ = net.ParseCIDR("f::f/128")
		felixServer.ip4 = &ipv4
		felixServer.ip6 = &ipv6
	})

	AfterEach(func() {

		// Clean up the symlink we created
		os.Remove("/run/vpp/stats.sock")

		// Clean up the VPP container
		testutils.TeardownVPP()
	})

	Describe("Startup config", func() {
		Context("Configuring startup policies", func() {
			It("Should add the startup host policies", func() {
				By("Creating all pods ipset with no pods")
				err := felixServer.createAllPodsIpset()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create all pods ipset")
				expectNpolIPSetContain(vpp, []string{"[ipset#0;ip;]"}, []string{})

				By("Creating EndpointToHostPolicy with default rule (deny)")
				err = felixServer.createEndpointToHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create endpointToHost policy")
				expectNpolPoliciesContain(vpp, []string{"tx:[rule#0;deny][src==[ipset#0;"}, []string{})

				By("changing EndpointToHostPolicy to ACCEPT")
				felixServer.felixConfig.DefaultEndpointToHostAction = "ACCEPT"
				err = felixServer.createEndpointToHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create endpointToHost policy")
				expectNpolPoliciesContain(vpp, []string{"tx:[rule#1;allow][src==[ipset#0;"}, []string{})

				By("creating AllowFromHostPolicy")
				err = felixServer.createAllowFromHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create allowFromHost policy")
				expectNpolPoliciesContain(vpp, []string{"tx:[rule#2;allow][src==1.1.1.1/32,src==f::f/128,]\n  rx:[rule#3;allow][dst==[ipset#0;ip;],]"}, []string{})

				By("creating allowToHostPolicy")
				err = felixServer.createAllowToHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create allowToHostPolicy")
				expectNpolPoliciesContain(vpp, []string{"tx:[rule#4;allow][dst==1.1.1.1/32,dst==f::f/128,]\n  rx:[rule#5;allow][src==1.1.1.1/32,src==f::f/128,]"}, []string{})

				By("creating default failsafe policies")
				err = felixServer.createFailSafePolicies()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create failSafe policies")
				expectNpolPoliciesContain(vpp, []string{
					"tx:[rule#6;allow][proto==TCP,dst==22,]\n  tx:[rule#7;allow][proto==UDP,dst==68,]\n",
					"tx:[rule#8;allow][proto==TCP,dst==179,]\n  tx:[rule#9;allow][proto==TCP,dst==2379,]",
					"tx:[rule#10;allow][proto==TCP,dst==2380,]\n  tx:[rule#11;allow][proto==TCP,dst==5473,]",
					"tx:[rule#12;allow][proto==TCP,dst==6443,]\n  tx:[rule#13;allow][proto==TCP,dst==6666,]",
					"tx:[rule#14;allow][proto==TCP,dst==6667,]\n  rx:[rule#15;allow][proto==UDP,dst==53,]",
					"rx:[rule#16;allow][proto==UDP,dst==67,]\n  rx:[rule#17;allow][proto==TCP,dst==179,]",
					"rx:[rule#18;allow][proto==TCP,dst==2379,]\n  rx:[rule#19;allow][proto==TCP,dst==2380,]",
					"rx:[rule#20;allow][proto==TCP,dst==5473,]\n  rx:[rule#21;allow][proto==TCP,dst==6443,]",
					"rx:[rule#22;allow][proto==TCP,dst==6666,]\n  rx:[rule#23;allow][proto==TCP,dst==6667,]",
				}, []string{})

				By("creating custom failsafe policies")
				felixServer.felixConfig.FailsafeInboundHostPorts = []felixConfig.ProtoPort{{Protocol: "TCP", Port: 22}}
				felixServer.felixConfig.FailsafeOutboundHostPorts = []felixConfig.ProtoPort{}
				err = felixServer.createFailSafePolicies()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create failSafe policies")
				expectNpolPoliciesContain(vpp, []string{"tx:[rule#24;allow][proto==TCP,dst==22,]"}, []string{})
			})
		})

	})

	Describe("Runtime config", func() {
		wepId := &proto.WorkloadEndpointID{
			OrchestratorId: "orch",
			WorkloadId:     "wl",
			EndpointId:     "ep"}
		wepEp := &proto.WorkloadEndpoint{}
		wepUpdate := &proto.WorkloadEndpointUpdate{
			Id:       wepId,
			Endpoint: wepEp}
		_, ipnet, _ := net.ParseCIDR("10.0.0.1/32")
		localWepId := &WorkloadEndpointID{OrchestratorID: wepId.OrchestratorId,
			WorkloadID: wepId.WorkloadId,
			EndpointID: wepId.EndpointId}
		var podSwIfIndex uint32
		Context("Adding and removing pods", func() {
			BeforeEach(func() {
				err := felixServer.createAllPodsIpset()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create all pods ipset")
				podSwIfIndex = CreateLoopbackToMockPodInterface(felixServer.vpp, log)
				err = felixServer.createAllowFromHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create allowFromHost policy")
				Expect(err).ToNot(HaveOccurred())
				felixServer.workloadAdded(localWepId, podSwIfIndex, "tun", []*net.IPNet{ipnet})

			})
			It("Should update pods ipset at workload add/remove", func() {
				expectNpolIPSetContain(vpp, []string{"[ipset#0;ip;10.0.0.1,]"}, []string{})
				felixServer.WorkloadRemoved(localWepId, []*net.IPNet{ipnet})
				expectNpolIPSetContain(vpp, []string{}, []string{"[ipset#0;ip;10.0.0.1,]"})
			})
			It("Should add and remove pod policies", func() {
				By("adding the workload endpoint update")
				err := felixServer.handleWorkloadEndpointUpdate(wepUpdate, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle workload endpoint update")
				expectNpolInterfacesContain(vpp, []string{"sw_if_index=" + fmt.Sprint(podSwIfIndex)}, []string{})
				By("adding the active policy update")
				pol := &proto.ActivePolicyUpdate{
					Id: &proto.PolicyID{
						Name: "pol",
						Tier: "tier",
					},
					Policy: &proto.Policy{
						InboundRules:  []*proto.Rule{{Action: "deny", DstPorts: []*proto.PortRange{{First: 3050, Last: 3060}}}, {Action: "allow", DstNet: []string{"6.6.6.6/24"}}},
						OutboundRules: []*proto.Rule{{Action: "deny", SrcPorts: []*proto.PortRange{{First: 4050, Last: 4060}}}, {Action: "allow", SrcNet: []string{"7.7.7.7/24"}}},
					},
				}
				err = felixServer.handleActivePolicyUpdate(pol, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle active policy update")
				expectNpolPoliciesContain(vpp, []string{
					";deny][dst==[3050-3060]",
					";allow][dst==6.6.6.0/24,]",
					";deny][src==[4050-4060],]",
					";allow][src==7.7.7.0/24,]",
				}, []string{})

				By("updating the wep to use the policy")
				err = felixServer.handleWorkloadEndpointUpdate(&proto.WorkloadEndpointUpdate{
					Id: wepId,
					Endpoint: &proto.WorkloadEndpoint{
						Tiers: []*proto.TierInfo{{
							Name:            "tier",
							IngressPolicies: []string{"pol"},
							EgressPolicies:  []string{"pol"},
						}},
					}}, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle workload endpoint update")
				expectNpolInterfacesContain(vpp, []string{";allow][src==7.7.7.0/24,]"}, []string{})

				By("updating the existing active policy update to change action")
				pol.Policy.InboundRules[0].Action = "allow"
				err = felixServer.handleActivePolicyUpdate(pol, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle active policy update")
				expectNpolPoliciesContain(vpp, []string{";allow][dst==[3050-3060]"}, []string{";deny][dst==[3050-3060]"})

				By("deleting the existing active policy")
				polR := &proto.ActivePolicyRemove{
					Id: &proto.PolicyID{
						Name: "pol",
						Tier: "tier",
					},
				}
				err = felixServer.handleActivePolicyRemove(polR, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle active policy remove")
				expectNpolPoliciesContain(vpp, []string{}, []string{";deny][dst==[3050-3060]"})
				wepR := &proto.WorkloadEndpointRemove{
					Id: wepId,
				}
				felixServer.WorkloadRemoved(localWepId, []*net.IPNet{ipnet})
				err = felixServer.handleWorkloadEndpointRemove(wepR, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle workload endpoint remove")
				vpp.DeleteLoopback(podSwIfIndex)
				npolOutput, err := vpp.RunCli("show npol interfaces")
				Expect(err).ToNot(HaveOccurred(),
					"failed to show npol interfaces from vpp cli")
				Expect(npolOutput).To(Equal("Interfaces with policies configured:\n"))
			})
		})
		Context("Ipam pool updates", func() {
			It("Should handle ipam pool updates", func() {
				err := vpp.CnatSetSnatAddresses(ipv4, ipv6)
				if err != nil {
					log.Errorf("Failed to configure SNAT addresses %v", err)
				}
				By("adding a new ipam pool")
				myIpamPool := &proto.IPAMPool{
					Cidr:     "3.3.0.0/16",
					IpipMode: "Always",
				}
				err = felixServer.handleIpamPoolUpdate(&proto.IPAMPoolUpdate{
					Id:   "ipampool",
					Pool: myIpamPool,
				}, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle ipam pool update")
				Expect(felixServer.ippoolmap["ipampool"]).To(Equal(myIpamPool))
				expectCnatSnatContain(vpp, []string{"3.3.0.0/16"}, []string{})

				By("updating an existing ipam pool")
				myIpamPool = &proto.IPAMPool{
					Cidr:     "3.4.0.0/16",
					IpipMode: "Always",
				}
				err = felixServer.handleIpamPoolUpdate(&proto.IPAMPoolUpdate{
					Id:   "ipampool",
					Pool: myIpamPool,
				}, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle ipam pool update")
				Expect(felixServer.ippoolmap["ipampool"]).To(Equal(myIpamPool))
				expectCnatSnatContain(vpp, []string{"3.4.0.0/16"}, []string{"3.3.0.0/16"})
				By("removing the ipam pool")
				err = felixServer.handleIpamPoolRemove(&proto.IPAMPoolRemove{
					Id: "ipampool",
				}, false)
				Expect(felixServer.ippoolmap["ipampool"]).To(BeNil())
				expectCnatSnatContain(vpp, []string{}, []string{"3.4.0.0/16"})
			})
		})
		Context("HostMetadata updates", func() {
			BeforeEach(func() {
				err := felixServer.createAllPodsIpset()
				err = felixServer.createAllowFromHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create allowFromHost policy")
			})
			It("should handle hostMetadataV4V6 updates of own node", func() {
				By("receiving a hostmetadatav4v6 update of own node")
				go func() {
					<-felixServer.GotOurNodeBGPchan
				}()
				nodeName := "host"
				config.NodeName = &nodeName
				err := felixServer.handleHostMetadataV4V6Update(&proto.HostMetadataV4V6Update{
					Hostname: "host",
					Ipv4Addr: "5.5.5.5/32",
					Ipv6Addr: "f::f/128",
				}, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostMetadataV4V6Update")
				expectCnatSnatContain(vpp, []string{"ip4: 5.5.5.5;0", "ip6: f::f;0"}, []string{})

				By("receiving a hostmetadatav4v6 remove of own node")
				err = felixServer.handleHostMetadataV4V6Remove(&proto.HostMetadataV4V6Remove{
					Hostname: "host",
				}, false)
				Expect(err).To(Equal(NodeWatcherRestartError{}),
					"failed to handle hostMetadataV4V6Remove")
			})
		})
		Context("HostEndpoint updates", func() {
			BeforeEach(func() {
				err := felixServer.createAllPodsIpset()
				err = felixServer.createAllowFromHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create allowFromHost policy")
				err = felixServer.createAllowToHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create allowToHostPolicy")
				err = felixServer.createFailSafePolicies()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create failSafe policies")
				err = felixServer.createEndpointToHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create EndpointToHost policies")
			})
			It("should warn about non existing interface name hep", func() {
				err := felixServer.handleHostEndpointUpdate(
					&proto.HostEndpointUpdate{
						Id: &proto.HostEndpointID{
							EndpointId: "hep",
						},
						Endpoint: &proto.HostEndpoint{
							Name: "no-uplink",
						},
					}, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				expectNpolInterfacesContain(vpp, []string{}, []string{"sw_if_index=1"})
			})
			It("Should handle wildcard host endpoint", func() {
				err := felixServer.handleHostEndpointUpdate(
					&proto.HostEndpointUpdate{
						Id: &proto.HostEndpointID{
							EndpointId: "hep",
						},
						Endpoint: &proto.HostEndpoint{
							Name: "*",
						},
					}, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				expectNpolInterfacesContain(vpp, []string{"sw_if_index=1"}, []string{})
			})
			It("Should handle host endpoint defined by expected IPs", func() {
				err := felixServer.handleHostEndpointUpdate(
					&proto.HostEndpointUpdate{
						Id: &proto.HostEndpointID{
							EndpointId: "hep",
						},
						Endpoint: &proto.HostEndpoint{
							Name:              "",
							ExpectedIpv4Addrs: []string{"10.0.100.0"},
						},
					}, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				expectNpolInterfacesContain(vpp, []string{"sw_if_index=1"}, []string{})
			})
			It("Should handle empty host endpoint update, dropping all traffic except failsafe", func() {
				err := felixServer.handleHostEndpointUpdate(
					&proto.HostEndpointUpdate{
						Id: &proto.HostEndpointID{
							EndpointId: "hep",
						},
						Endpoint: &proto.HostEndpoint{
							Name: "uplink",
						},
					}, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				// should contain the failsafe policies and drop by default
				expectNpolInterfacesContain(vpp, []string{"proto==TCP,dst==6667", "sw_if_index=2 ]\n  rx:\n   rx-policy-default:1 "}, []string{})
			})
			It("Should handle non empty host endpoint updates", func() {
				By("adding a new hep update")
				pol := &proto.ActivePolicyUpdate{
					Id: &proto.PolicyID{
						Name: "pol",
						Tier: "tier",
					},
					Policy: &proto.Policy{
						InboundRules:  []*proto.Rule{{Action: "deny", DstPorts: []*proto.PortRange{{First: 3050, Last: 3060}}}, {Action: "allow", DstNet: []string{"6.6.6.6/24"}}},
						OutboundRules: []*proto.Rule{{Action: "deny", SrcPorts: []*proto.PortRange{{First: 4050, Last: 4060}}}, {Action: "allow", SrcNet: []string{"7.7.7.7/24"}}},
					},
				}
				err := felixServer.handleActivePolicyUpdate(pol, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle active policy update")
				hep := &proto.HostEndpointUpdate{
					Id: &proto.HostEndpointID{
						EndpointId: "hep",
					},
					Endpoint: &proto.HostEndpoint{
						Name: "uplink",
						Tiers: []*proto.TierInfo{{
							Name:            "tier",
							IngressPolicies: []string{"pol"},
							EgressPolicies:  []string{"pol"},
						}},
					},
				}
				err = felixServer.handleHostEndpointUpdate(
					hep, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				// should contain the failsafe policies, userdefined policy, and drop by default
				expectNpolInterfacesContain(vpp, []string{"proto==TCP,dst==6667", "[3050-3060]", "sw_if_index=2 ]\n  rx:\n   rx-policy-default:1 "}, []string{})

				By("updating the existing new hep update policy")
				pol = &proto.ActivePolicyUpdate{
					Id: &proto.PolicyID{
						Name: "pol",
						Tier: "tier",
					},
					Policy: &proto.Policy{
						InboundRules:  []*proto.Rule{{Action: "deny", DstPorts: []*proto.PortRange{{First: 3070, Last: 3080}}}, {Action: "allow", DstNet: []string{"6.6.6.6/24"}}},
						OutboundRules: []*proto.Rule{{Action: "deny", SrcPorts: []*proto.PortRange{{First: 4050, Last: 4060}}}, {Action: "allow", SrcNet: []string{"7.7.7.7/24"}}},
					},
				}
				err = felixServer.handleActivePolicyUpdate(pol, false)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle active policy update")
				// should contain the new userdefined policy and not contain the old userdefined policy
				expectNpolInterfacesContain(vpp, []string{"[3070-3080]"}, []string{"[3050-3060]"})

				By("updating the existing new hep by removing egress")
				hep = &proto.HostEndpointUpdate{
					Id: &proto.HostEndpointID{
						EndpointId: "hep",
					},
					Endpoint: &proto.HostEndpoint{
						Name: "uplink",
						Tiers: []*proto.TierInfo{{
							Name:            "tier",
							IngressPolicies: []string{"pol"},
						}},
					},
				}
				err = felixServer.handleHostEndpointUpdate(
					hep, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				npolOutput, err := vpp.RunCli("show npol interfaces")
				Expect(err).ToNot(HaveOccurred(),
					"failed to show npol interfaces from vpp cli")
				Expect(npolOutput).To(Not(ContainSubstring("7.7.7.7")))
				By("updating the existing new hep without changes")
				err = felixServer.handleHostEndpointUpdate(
					hep, false,
				)
				Expect(err).ToNot(HaveOccurred(),
					"failed to handle hostendpoint update")
				expectNpolInterfacesContain(vpp, []string{}, []string{})
				npolOutput2, err := vpp.RunCli("show npol interfaces")
				Expect(err).ToNot(HaveOccurred(),
					"failed to show npol interfaces from vpp cli")
				Expect(npolOutput2).To(Equal(npolOutput))
				By("deleting the existing hep")
				err = felixServer.handleHostEndpointRemove(
					&proto.HostEndpointRemove{
						Id: &proto.HostEndpointID{
							EndpointId: "hep",
						},
					}, false,
				)
				// no more failsafe because user defined policies are gone
				// no more user defined policies
				expectNpolInterfacesContain(vpp, []string{}, []string{"proto==TCP,dst==179", "[3070-3080]"})
			})
		})
		Context("Config update", func() {
			var configs map[string]string
			BeforeEach(func() {
				go func() {
					<-felixServer.FelixConfigChan
				}()
				configs = map[string]string{
					"FailsafeInboundHostPorts":    "none",
					"FailsafeOutboundHostPorts":   "none",
					"DefaultEndpointToHostAction": "ACCEPT",
				}
				err := felixServer.createAllPodsIpset()
				err = felixServer.createEndpointToHostPolicy()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create EndpointToHost policies")
				err = felixServer.createFailSafePolicies()
				Expect(err).ToNot(HaveOccurred(),
					"failed to create failSafe policies")
			})
			It("should error out when state is not connected", func() {
				felixServer.state = StateDisconnected
				err := felixServer.handleConfigUpdate(
					&proto.ConfigUpdate{
						Config: configs,
					},
				)
				Expect(err).To(HaveOccurred(),
					"failed to error handle config update")
			})
			It("should update felix config", func() {
				By("adding new felix config, that changes endpointToHostAction and removes failsafe rules")
				felixServer.state = StateConnected
				err := felixServer.handleConfigUpdate(
					&proto.ConfigUpdate{
						Config: configs,
					},
				)
				Expect(err).To(Not(HaveOccurred()),
					"failed to error handle config update")
				expectNpolPoliciesContain(vpp, []string{"allow][src==[ipset#0;ip;]"}, []string{"dst==5473"})
				By("existing new felix config")
				configs = map[string]string{
					"FailsafeInboundHostPorts":    "none",
					"FailsafeOutboundHostPorts":   "none",
					"DefaultEndpointToHostAction": "DROP",
				}
				felixServer.state = StateConnected
				err = felixServer.handleConfigUpdate(
					&proto.ConfigUpdate{
						Config: configs,
					},
				)
				Expect(err).To(Not(HaveOccurred()),
					"failed to error handle config update")
				By("re-changing endpointToHostAction")
				expectNpolPoliciesContain(vpp, []string{"deny][src==[ipset#0;ip;]"}, []string{})
			})

		})
		Context("IPSet updates", func() {
			It("should handle ipset creating, updating and removing", func() {
				By("adding two ipsets")
				felixServer.handleIpsetUpdate(
					&proto.IPSetUpdate{
						Id:      "myipset-1",
						Members: []string{"55.55.0.0"},
					}, false,
				)
				felixServer.handleIpsetUpdate(
					&proto.IPSetUpdate{
						Id:      "myipset-2",
						Members: []string{"66.66.0.0"},
					}, false,
				)
				expectNpolIPSetContain(vpp, []string{";ip;55.55.0.0,]", ";ip;66.66.0.0,]"}, []string{})

				By("updating one of the two ipsets")
				felixServer.handleIpsetDeltaUpdate(
					&proto.IPSetDeltaUpdate{
						Id:             "myipset-1",
						AddedMembers:   []string{"55.77.0.0"},
						RemovedMembers: []string{"55.55.0.0"},
					}, false,
				)
				expectNpolIPSetContain(vpp, []string{";ip;55.77.0.0,]", ";ip;66.66.0.0,]"}, []string{";ip;55.55.0.0,]"})

				By("removing one of the two ipsets")
				felixServer.handleIpsetRemove(
					&proto.IPSetRemove{
						Id: "myipset-2",
					}, false,
				)
				expectNpolIPSetContain(vpp, []string{";ip;55.77.0.0,]"}, []string{";ip;66.66.0.0,]"})
			})
		})
		Context("Profiles updates", func() {
			It("should handle profiles creating, updating, and removing", func() {
				By("creating a profile")
				felixServer.handleActiveProfileUpdate(
					&proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{
							Name: "myprofile",
						},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{{Action: "deny", DstPorts: []*proto.PortRange{{First: 3050, Last: 3060}}}, {Action: "allow", DstNet: []string{"6.6.6.6/24"}}},
						},
					}, false,
				)
				expectNpolPoliciesContain(vpp, []string{"deny][dst==[3050-3060]"}, []string{})
				By("updating the profile")
				felixServer.handleActiveProfileUpdate(
					&proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{
							Name: "myprofile",
						},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{{Action: "allow", DstPorts: []*proto.PortRange{{First: 3050, Last: 3060}}}, {Action: "allow", DstNet: []string{"6.6.6.6/24"}}},
						},
					}, false,
				)
				expectNpolPoliciesContain(vpp, []string{"allow][dst==[3050-3060]"}, []string{})
				By("removing the profile")
				felixServer.handleActiveProfileRemove(
					&proto.ActiveProfileRemove{
						Id: &proto.ProfileID{
							Name: "myprofile",
						},
					}, false,
				)
				expectNpolPoliciesContain(vpp, []string{}, []string{"3050-3060]"})
			})
		})
	})

})

func expectNpolPoliciesContain(vpp *vpplink.VppLink, substrsToFind []string, substrsNotToFind []string) {
	out, err := vpp.RunCli("show npol policies verbose")
	Expect(err).ToNot(HaveOccurred(),
		"failed to show npol policies from vpp cli")
	for _, substr := range substrsToFind {
		Expect(out).To(ContainSubstring(substr))
	}
	for _, substr := range substrsNotToFind {
		Expect(out).To(Not(ContainSubstring(substr)))
	}
}

func expectNpolIPSetContain(vpp *vpplink.VppLink, substrsToFind []string, substrsNotToFind []string) {
	out, err := vpp.RunCli("show npol ipset")
	Expect(err).ToNot(HaveOccurred(),
		"failed to show npol ipset from vpp cli")
	for _, substr := range substrsToFind {
		Expect(out).To(ContainSubstring(substr))
	}
	for _, substr := range substrsNotToFind {
		Expect(out).To(Not(ContainSubstring(substr)))
	}
}

func expectNpolInterfacesContain(vpp *vpplink.VppLink, substrsToFind []string, substrsNotToFind []string) {
	out, err := vpp.RunCli("show npol interfaces")
	Expect(err).ToNot(HaveOccurred(),
		"failed to show npol interfaces from vpp cli")
	for _, substr := range substrsToFind {
		Expect(out).To(ContainSubstring(substr))
	}
	for _, substr := range substrsNotToFind {
		Expect(out).To(Not(ContainSubstring(substr)))
	}
}

func expectCnatSnatContain(vpp *vpplink.VppLink, substrsToFind []string, substrsNotToFind []string) {
	out, err := vpp.RunCli("show cnat snat")
	Expect(err).ToNot(HaveOccurred(),
		"failed to show cnat snat from vpp cli")
	for _, substr := range substrsToFind {
		Expect(out).To(ContainSubstring(substr))
	}
	for _, substr := range substrsNotToFind {
		Expect(out).To(Not(ContainSubstring(substr)))
	}
}

func CreateLoopbackAndTaggingItAsMain(vpp *vpplink.VppLink, log *logrus.Logger) {
	swIfIndex1, err := vpp.CreateLoopback(net.HardwareAddr{})
	Expect(err).ToNot(HaveOccurred(), "failed to create loopback")
	err = vpp.SetInterfaceTag(swIfIndex1, "host-uplink")
	Expect(err).ToNot(HaveOccurred(), "failed to tag interface")
}

func CreateLoopbackToMockPodInterface(vpp *vpplink.VppLink, log *logrus.Logger) uint32 {
	swIfIndex, err := vpp.CreateLoopback(net.HardwareAddr{})
	Expect(err).ToNot(HaveOccurred(), "failed to create loopback")
	return swIfIndex
}
