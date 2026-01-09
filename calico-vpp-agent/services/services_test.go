package services

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/testutils"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"

	"github.com/sirupsen/logrus"
	apiv1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Names of integration tests arguments
const (
	VppImageArgName           = "VPP_IMAGE"
	VppBinaryArgName          = "VPP_BINARY"
	VppContainerExtraArgsName = "VPP_CONTAINER_EXTRA_ARGS"
)

// TestServicesIntegration runs all the ginkgo integration test inside services package
func TestServicesIntegration(t *testing.T) {
	// skip test if test run is not integration test run (prevent accidental run of integration tests using go test ./...)
	_, isIntegrationTestRun := os.LookupEnv(VppImageArgName)
	if !isIntegrationTestRun {
		t.Skip("skipping services integration tests (set INTEGRATION_TEST env variable to run these tests)")
	}

	// integrate gomega and ginkgo -> register all Services integration tests
	RegisterFailHandler(Fail)
	RunSpecs(t, "Services Integration Suite")
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

var _ = Describe("Service creation functionality", func() {
	var (
		log           *logrus.Logger
		vpp           *vpplink.VppLink
		serviceServer *Server
		uplinkSwIf    uint32
	)

	BeforeEach(func() {
		log = logrus.New()
		// Set unique container name for Services tests
		testutils.VPPContainerName = "services-tests-vpp"
		testutils.StartVPP()
		vpp, uplinkSwIf = testutils.ConfigureVPP(log)
		common.VppManagerInfo = &config.VppManagerInfo{
			UplinkStatuses: map[string]config.UplinkStatus{
				"uplink": {
					SwIfIndex:    uplinkSwIf,
					TapSwIfIndex: uplinkSwIf,
					IsMain:       true,
				},
			},
			PhysicalNets: map[string]config.PhysicalNetwork{},
		}
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
		k8sclient, err := kubernetes.NewForConfig(&rest.Config{})
		if err != nil {
			log.Fatalf("cannot create k8s client %s", err)
		}
		_, serviceip, err := net.ParseCIDR("10.96.0.1/24")
		config.ServiceCIDRs = &[]*net.IPNet{serviceip}
		serviceServer = NewServiceServer(vpp, k8sclient, log.WithFields(logrus.Fields{"component": "services"}))
		_, ipv4net, err := net.ParseCIDR("1.1.1.1/32")
		_, ipv6net, err := net.ParseCIDR("f::f/128")
		serviceServer.SetOurBGPSpec(&common.LocalNodeSpec{
			IPv4Address: ipv4net,
			IPv6Address: ipv6net,
		})
		err = vpp.CnatSetSnatAddresses(ipv4net.IP, ipv6net.IP)
		Expect(err).ToNot(HaveOccurred(),
			"failed to configure SNAT addresses")
	})

	AfterEach(func() {

		// Clean up the symlink we created
		os.Remove("/run/vpp/stats.sock")

		// Clean up the VPP container
		testutils.TeardownVPP()
	})

	Describe("Startup config", func() {
		Context("Configuring snat", func() {
			It("Should configure snat addresses and exclude prefixes", func() {
				err := serviceServer.configureSnat()
				Expect(err).To(BeNil())
				cnatsnatoutput, err := vpp.RunCli("show cnat snat")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get cnatsnat output from vpp cli")
				By("adding snat addresses")
				Expect(cnatsnatoutput).To(ContainSubstring("ip4: 1.1.1.1;0\n  ip6: f::f;0"),
					"cannot find cnat snat addresses")
				By("excluding services prefixes")
				Expect(cnatsnatoutput).To(ContainSubstring("0: 10.96.0.0/24"),
					"cannot find the service ips in excluded ips")
				By("excluding node ips")
				Expect(cnatsnatoutput).To(ContainSubstring("0: 1.1.1.1/32"),
					"cannot find the ipv4 node address in excluded ips")
				Expect(cnatsnatoutput).To(ContainSubstring("0: f::f/128"),
					"cannot find the ipv6 node address in excluded ips")
			})
			It("Should not fail when service CIDRs contain only IPv4", func() {
				By("configuring only IPv4 service CIDR")
				_, serviceip, err := net.ParseCIDR("10.97.0.0/24")
				Expect(err).To(BeNil())
				config.ServiceCIDRs = &[]*net.IPNet{serviceip}

				err = serviceServer.configureSnat()
				Expect(err).To(BeNil())

				cnatsnatoutput, err := vpp.RunCli("show cnat snat")
				Expect(err).ToNot(HaveOccurred())
				Expect(cnatsnatoutput).To(ContainSubstring("10.97.0.0/24"))
			})
			It("Should not panic if ServiceCIDRs is empty", func() {
				By("configuring empty service CIDRs")
				config.ServiceCIDRs = &[]*net.IPNet{}

				err := serviceServer.configureSnat()
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("Services creation", func() {
		Context("handling service annotations", func() {
			It("should handle missing annotations gracefully", func() {
				By("passing empty annotations map")
				svc := serviceServer.ParseServiceAnnotations(map[string]string{}, "mysvc")

				Expect(svc).ToNot(BeNil())
				Expect(int(svc.hashConfig)).To(Equal(0))
				Expect(string(svc.lbType)).To(Equal(""))
				Expect(svc.keepOriginalPacket).To(Equal(false))
			})
			It("should ignore unknown annotations", func() {
				annotations := map[string]string{
					"some.random/annotation": "value",
				}

				svc := serviceServer.ParseServiceAnnotations(annotations, "mysvc")

				Expect(svc).ToNot(BeNil())
				Expect(int(svc.hashConfig)).To(Equal(0))
				Expect(string(svc.lbType)).To(Equal(""))
				Expect(svc.keepOriginalPacket).To(Equal(false))
			})
			It("should tolerate extra spaces in hash config", func() {
				annotations := map[string]string{
					"cni.projectcalico.org/vppHashConfig": " symmetric , dstport ",
				}

				svc := serviceServer.ParseServiceAnnotations(annotations, "mysvc")

				Expect(svc.hashConfig).To(Equal(
					types.FlowHashSymetric + types.FlowHashDstPort,
				))
			})
			It("should parse service annotations correctly", func() {
				annotations := make(map[string]string)
				annotations["cni.projectcalico.org/vppHashConfig"] = "symmetric, iproto, dstport, srcport"
				annotations["cni.projectcalico.org/vppLBType"] = "maglev"
				svc := serviceServer.ParseServiceAnnotations(annotations, "mysvc")
				Expect(svc.keepOriginalPacket).To(BeFalse())
				Expect(svc.lbType).To(Equal(lbTypeMaglev))
				Expect(svc.hashConfig).To(Equal(types.FlowHashSymetric + types.FlowHashProto + types.FlowHashSrcPort + types.FlowHashDstPort))
			})
		})
		Context("Creating kubernetes services", func() {
			ITPolicy := new(apiv1.ServiceInternalTrafficPolicy)
			*ITPolicy = apiv1.ServiceInternalTrafficPolicyCluster
			myPortName := new(string)
			*myPortName = "myport"
			It("should return empty entries when service has no ports", func() {
				svc := &apiv1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "emptyports",
					},
					Spec: apiv1.ServiceSpec{
						ClusterIPs: []string{"5.5.5.5"},
					},
				}

				epSlicesMap := map[string]*discoveryv1.EndpointSlice{}

				localService := serviceServer.GetLocalService(svc, epSlicesMap)
				Expect(localService.Entries).To(BeEmpty())
			})
			It("should return empty backends when no endpoint slices exist for service", func() {
				mySvcPort := int32(80)
				svc := &apiv1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "noeps",
					},
					Spec: apiv1.ServiceSpec{
						Ports:                 []apiv1.ServicePort{{Protocol: apiv1.ProtocolTCP, Port: mySvcPort}},
						ClusterIPs:            []string{"6.6.6.6"},
						InternalTrafficPolicy: ITPolicy,
					},
				}

				localService := serviceServer.GetLocalService(svc, map[string]*discoveryv1.EndpointSlice{})
				Expect(localService.Entries[0].Backends).To(BeEmpty())
			})
			It("should return empty backends for endpoints with empty addresses", func() {
				mySvcPort := int32(8080)
				myBackendPort := int32(9090)

				svc := &apiv1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "emptyaddr",
					},
					Spec: apiv1.ServiceSpec{
						Ports: []apiv1.ServicePort{{Protocol: apiv1.ProtocolTCP,
							Port:       mySvcPort,
							Name:       *myPortName,
							TargetPort: intstr.FromInt(int(myBackendPort))}},
						ClusterIPs:            []string{"7.7.7.7"},
						InternalTrafficPolicy: ITPolicy,
					},
				}

				epSlicesMap := map[string]*discoveryv1.EndpointSlice{
					"emptyaddr": {
						Endpoints: []discoveryv1.Endpoint{
							{Addresses: []string{}},
						},
						Ports: []discoveryv1.EndpointPort{
							{Port: &myBackendPort, Name: myPortName},
						},
					},
				}

				localService := serviceServer.GetLocalService(svc, epSlicesMap)
				Expect(localService.Entries[0].Backends).To(BeEmpty())
			})
			It("should support multiple backends in one endpoint slice", func() {
				mySvcPort := int32(8081)
				myBackendPort := int32(8082)

				svc := &apiv1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "multibackend",
					},
					Spec: apiv1.ServiceSpec{
						Ports:                 []apiv1.ServicePort{{Protocol: apiv1.ProtocolTCP, Port: mySvcPort, Name: *myPortName, TargetPort: intstr.FromInt(int(myBackendPort))}},
						ClusterIPs:            []string{"8.8.8.8"},
						InternalTrafficPolicy: ITPolicy,
					},
				}

				epSlicesMap := map[string]*discoveryv1.EndpointSlice{
					"multibackend": {
						Endpoints: []discoveryv1.Endpoint{
							{Addresses: []string{"10.0.0.1"}},
							{Addresses: []string{"10.0.0.2"}},
						},
						Ports: []discoveryv1.EndpointPort{
							{Port: &myBackendPort, Name: myPortName},
						},
					},
				}

				localService := serviceServer.GetLocalService(svc, epSlicesMap)
				Expect(localService).ToNot(BeNil())
				Expect(localService.Entries).To(HaveLen(1))
				Expect(localService.Entries[0].Backends).To(HaveLen(2))
			})
			It("should create cnat translations for services", func() {
				By("creating a service with cluster ip")
				myBackendIp := "3.3.3.3"
				myBackendPort := int32(3051)
				mySvc := "mysvc"
				mySvcIp := "4.4.4.4"
				mySvcPort := int32(3033)
				svc := &apiv1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: mySvc,
					},
					Spec: apiv1.ServiceSpec{
						Ports:                 []apiv1.ServicePort{{Protocol: apiv1.ProtocolTCP, Port: mySvcPort, Name: *myPortName, TargetPort: intstr.FromInt(int(myBackendPort))}},
						ClusterIPs:            []string{mySvcIp},
						InternalTrafficPolicy: ITPolicy,
					},
				}
				epSlicesMap := make(map[string]*discoveryv1.EndpointSlice)
				epSlicesMap[mySvc] = &discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name: "myepslice",
					},
					Ports: []discoveryv1.EndpointPort{
						{
							Port: &myBackendPort,
							Name: myPortName,
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{myBackendIp},
						},
					},
				}
				localService := serviceServer.GetLocalService(svc, epSlicesMap)

				Expect(localService).To(Equal(&LocalService{
					SpecificRoutes: []net.IP{},
					ServiceID:      "/" + mySvc,
					Entries: []types.CnatTranslateEntry{
						{
							Endpoint: types.CnatEndpoint{
								Port: uint16(mySvcPort),
								IP:   net.ParseIP(mySvcIp),
							},
							Proto: types.TCP,
							Backends: []types.CnatEndpointTuple{
								{
									DstEndpoint: types.CnatEndpoint{
										Port: uint16(myBackendPort),
										IP:   net.ParseIP(myBackendIp),
									},
								},
							},
						},
					},
				}))
				serviceServer.handleServiceEndpointEvent(localService, nil)
				cnattroutput, err := vpp.RunCli("show cnat translation")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get cnat translations output from vpp cli")
				Expect(cnattroutput).To(ContainSubstring("4.4.4.4;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				By("creating a service with cluster ip and external ip")
				myExternalIp := "9.9.9.9"
				svc.Spec.ExternalIPs = []string{myExternalIp}
				localService = serviceServer.GetLocalService(svc, epSlicesMap)

				Expect(localService).To(Equal(&LocalService{
					SpecificRoutes: []net.IP{},
					ServiceID:      "/" + mySvc,
					Entries: []types.CnatTranslateEntry{
						{
							Endpoint: types.CnatEndpoint{
								Port: uint16(mySvcPort),
								IP:   net.ParseIP(mySvcIp),
							},
							Proto: types.TCP,
							Backends: []types.CnatEndpointTuple{
								{
									DstEndpoint: types.CnatEndpoint{
										Port: uint16(myBackendPort),
										IP:   net.ParseIP(myBackendIp),
									},
								},
							},
						},
						{
							Endpoint: types.CnatEndpoint{
								Port: uint16(mySvcPort),
								IP:   net.ParseIP(myExternalIp),
							},
							Proto: types.TCP,
							Backends: []types.CnatEndpointTuple{
								{
									DstEndpoint: types.CnatEndpoint{
										Port: uint16(myBackendPort),
										IP:   net.ParseIP(myBackendIp),
									},
								},
							},
						},
					},
				}))
				serviceServer.handleServiceEndpointEvent(localService, nil)
				cnattroutput, err = vpp.RunCli("show cnat translation")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get cnat translations output from vpp cli")
				Expect(cnattroutput).To(ContainSubstring("4.4.4.4;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				Expect(cnattroutput).To(ContainSubstring("9.9.9.9;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				By("creating a service with cluster ip, external ip and nodeport")
				svc.Spec.Type = apiv1.ServiceTypeNodePort
				nodePort := 9999
				svc.Spec.Ports[0].NodePort = int32(nodePort)
				localService = serviceServer.GetLocalService(svc, epSlicesMap)
				Expect(localService).To(Equal(&LocalService{
					SpecificRoutes: []net.IP{},
					ServiceID:      "/" + mySvc,
					Entries: []types.CnatTranslateEntry{
						{
							Endpoint: types.CnatEndpoint{
								Port: uint16(mySvcPort),
								IP:   net.ParseIP(mySvcIp),
							},
							Proto: types.TCP,
							Backends: []types.CnatEndpointTuple{
								{
									DstEndpoint: types.CnatEndpoint{
										Port: uint16(myBackendPort),
										IP:   net.ParseIP(myBackendIp),
									},
								},
							},
						},
						{
							Endpoint: types.CnatEndpoint{
								Port: uint16(mySvcPort),
								IP:   net.ParseIP(myExternalIp),
							},
							Proto: types.TCP,
							Backends: []types.CnatEndpointTuple{
								{
									DstEndpoint: types.CnatEndpoint{
										Port: uint16(myBackendPort),
										IP:   net.ParseIP(myBackendIp),
									},
								},
							},
						},
						{
							Endpoint: types.CnatEndpoint{
								Port: uint16(nodePort),
								IP:   net.ParseIP("1.1.1.1").To4(),
							},
							Proto:    types.TCP,
							IsRealIP: true,
							Backends: []types.CnatEndpointTuple{
								{
									DstEndpoint: types.CnatEndpoint{
										Port: uint16(myBackendPort),
										IP:   net.ParseIP(myBackendIp),
									},
								},
							},
						},
					},
				}))
				serviceServer.handleServiceEndpointEvent(localService, nil)
				cnattroutput, err = vpp.RunCli("show cnat translation")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get cnat translations output from vpp cli")
				Expect(cnattroutput).To(ContainSubstring("4.4.4.4;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				Expect(cnattroutput).To(ContainSubstring("9.9.9.9;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				Expect(cnattroutput).To(ContainSubstring("1.1.1.1;9999 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				By("updating the service to change the cluster ip")
				myNewSvcIp := "5.5.5.5"
				svc.Spec.ClusterIPs = []string{myNewSvcIp}
				newLocalService := serviceServer.GetLocalService(svc, epSlicesMap)
				Expect(newLocalService.Entries[0].Endpoint.IP).To(Equal(net.ParseIP(myNewSvcIp)))
				serviceServer.handleServiceEndpointEvent(newLocalService, localService)
				cnattroutput, err = vpp.RunCli("show cnat translation")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get cnat translations output from vpp cli")
				Expect(cnattroutput).To(ContainSubstring("5.5.5.5;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				Expect(cnattroutput).To(Not(ContainSubstring("4.4.4.4;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051")))
				By("deleting the service entries")
				serviceServer.handleServiceEndpointEvent(nil, newLocalService)
				cnattroutput, err = vpp.RunCli("show cnat translation")
				Expect(cnattroutput).To(BeEmpty())
				By("recreating the service")
				serviceServer.handleServiceEndpointEvent(newLocalService, nil)
				cnattroutput, err = vpp.RunCli("show cnat translation")
				Expect(cnattroutput).To(ContainSubstring("5.5.5.5;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				Expect(cnattroutput).To(ContainSubstring("9.9.9.9;3033 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				Expect(cnattroutput).To(ContainSubstring("1.1.1.1;9999 TCP lb:default fhc:0x9f(default)\n::;0->3.3.3.3;3051"))
				By("deleting the service by name")
				serviceServer.deleteServiceByName("/" + mySvc)
				cnattroutput, err = vpp.RunCli("show cnat translation")
				Expect(cnattroutput).To(BeEmpty())
			})
		})
	})
})
