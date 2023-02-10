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

package policy_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	felixconfig "github.com/projectcalico/calico/felix/config"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	//felixconfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	test "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common_tests"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	watchdog "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watch_dog"
	"github.com/projectcalico/vpp-dataplane/config"
	agentConf "github.com/projectcalico/vpp-dataplane/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
)

// Names of integration tests arguments
const (
	IntegrationTestEnableArgName = "INTEGRATION_TEST"
	VppImageArgName              = "VPP_IMAGE"
	VppBinaryArgName             = "VPP_BINARY"
	VppContainerExtraArgsName    = "VPP_CONTAINER_EXTRA_ARGS"
	testTimeout                  = "40s"
)

var t tomb.Tomb

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
	test.VppImage, found = os.LookupEnv(VppImageArgName)
	if !found {
		Expect(test.VppImage).ToNot(BeEmpty(), fmt.Sprintf("Please specify docker image containing "+
			"VPP binary using %s environment variable.", VppImageArgName))
	}
	test.VppBinary, found = os.LookupEnv(VppBinaryArgName)
	if !found {
		Expect(test.VppBinary).ToNot(BeEmpty(), fmt.Sprintf("Please specify VPP binary (full path) "+
			"inside docker image %s using %s environment variable.", test.VppImage, VppBinaryArgName))
	}

	vppContainerExtraArgsList, found := os.LookupEnv(VppContainerExtraArgsName)
	if found {
		test.VppContainerExtraArgs = append(test.VppContainerExtraArgs, strings.Split(vppContainerExtraArgsList, ",")...)
	}

})

var _ = Describe("Functionality of policy server using felix", func() {
	var (
		log          *logrus.Logger
		vpp          *vpplink.VppLink
		policyServer *policy.Server
		err          error
		cniServer    *cni.Server
		cmd          *exec.Cmd
		watchDog     *watchdog.WatchDog
	)
	BeforeEach(func() {
		log = logrus.New()
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))
	})

	JustBeforeEach(func() {
		test.StartVPP()
		vpp, _ = test.ConfigureVPP(log, true)
		// Additional configuration specific to policies test: add tap for host endpoints
		_, err = vpp.CreateTapV2(&types.TapV2{
			GenericVppInterface: types.GenericVppInterface{
				HostInterfaceName: test.UplinkIfName,
				HardwareAddr:      test.Mac("aa:bb:cc:dd:ee:01"),
			},
			Tag:   fmt.Sprintf("host-%s", test.UplinkIfName),
			Flags: types.TapFlagNone,
			// Host end of tap (it is located inside docker container)
			HostMtu:        1500,
			HostMacAddress: *test.Mac("aa:bb:cc:dd:ee:02"),
		})
		Expect(err).ToNot(HaveOccurred(), "Error creating mocked tap interface")

		_, err = vpp.CreateTapV2(&types.TapV2{
			GenericVppInterface: types.GenericVppInterface{
				HostInterfaceName: test.Uplink2IfName,
				HardwareAddr:      test.Mac("aa:bb:cc:dd:ee:03"),
			},
			Tag:   fmt.Sprintf("host-%s", test.Uplink2IfName),
			Flags: types.TapFlagNone,
			// Host end of tap (it is located inside docker container)
			HostMtu:        1500,
			HostMacAddress: *test.Mac("aa:bb:cc:dd:ee:04"),
		})
		Expect(err).ToNot(HaveOccurred(), "Error creating mocked tap interface")

		config.GetCalicoVppDebug().PoliciesEnabled = &config.True
		common.VppManagerInfo = &agentConf.VppManagerInfo{UplinkStatuses: []agentConf.UplinkStatus{{IsMain: true, SwIfIndex: 1}}}
		policyServer, err = policy.NewPolicyServer(vpp, log.WithFields(logrus.Fields{"component": "policy"}), false)
		Expect(err).ToNot(HaveOccurred(), "Failed to create policy server")
		cniServer = cni.NewCNIServer(vpp, policyServer, log.WithFields(logrus.Fields{"component": "cni"}))
		Go(policyServer.ServePolicy)
		log.Info("WAITING FOR FELIX CONFIG... please run felix")
		cmd = exec.Command("make", "fv")
		cmd.Env = os.Environ()
		cmd.Dir = "../../felix"
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		watchDog = watchdog.NewWatchDog(log.WithFields(logrus.Fields{"component": "watchDog"}), &t)
	})

	Describe("Creation of a workload endpoint", func() {
		Context("With creation of the pod in cni server", func() {
			const (
				ipAddress     = "1.2.3.44"
				interfaceName = "newInterface"
			)
			JustBeforeEach(func() {
				test.CreatePod()
				By("Getting Pod mock container's PID")
				containerPidOutput, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}",
					test.PodMockContainerName).Output()
				Expect(err).Should(BeNil(), "Failed to get pod mock container's PID string")
				containerPidStr := strings.ReplaceAll(string(containerPidOutput), "\n", "")
				By("Adding pod using CNI server")
				newPod := &proto.AddRequest{
					InterfaceName: interfaceName,
					Netns:         fmt.Sprintf("/proc/%s/ns/net", containerPidStr), // expecting mount of "/proc" from host
					ContainerIps:  []*proto.IPConfig{{Address: ipAddress + "/24"}},
					Workload: &proto.WorkloadIDs{
						// these values come from fv test
						Orchestrator: "k8s",
						Endpoint:     "eth0",
						Namespace:    "default",
						Pod:          "test-pod-44445555-idx1",
					},
				}
				cniServer.SetFelixConfig((&felixconfig.Config{}))
				cniServer.FetchBufferConfig()
				config.GetCalicoVppInterfaces().DefaultPodIfSpec = &config.InterfaceSpec{}
				config.GetCalicoVppFeatureGates().IPSecEnabled = &config.False
				config.GetCalicoVppDebug().GSOEnabled = &config.True
				reply, err := cniServer.Add(context.Background(), newPod)
				Expect(err).ToNot(HaveOccurred(), "Pod addition failed")
				Expect(reply.Successful).To(BeTrue(),
					fmt.Sprintf("Pod addition failed due to: %s", reply.ErrorMessage))
				By("Checking existence (and IP address) of interface tunnel at added pod's end")
				interfaceDetails, err := exec.Command("docker", "exec", test.PodMockContainerName,
					"ip", "address", "show", "dev", interfaceName).Output()
				log.Infof("%s", interfaceDetails)
				Expect(err).Should(BeNil(), "Failed to get added interface details from pod container")
				Expect(string(interfaceDetails)).Should(ContainSubstring(ipAddress),
					"Interface tunnel on new pod's end is either wrong configured "+
						"for IP address or doesn't exist at all")
			})
			Context("With creation of the workload in fv tests", func() {
				It("should configure a pod with policies", func() {
					cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should create a pod with a policy")
					err = cmd.Start()
					Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
					_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
					Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("addr=" + ipAddress))
					Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("1.9.9.1"))
					st, _ := vpp.RunCli("show capo int")
					fmt.Printf(st)
				})
				It("should configure a pod with default profiles", func() {
					cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should create a pod without")
					err = cmd.Start()
					Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
					_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
					Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("addr=" + ipAddress + "]\n  profiles"))
					st, _ := vpp.RunCli("show capo int")
					fmt.Printf(st)
				})
			})
		})
	})
	Describe("Creation of a host endpoint", func() {
		It("should have default policies on host interfaces", func() {
			Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("tx:[rule#0;deny][src==[ipset#0;ip;],]"))
			st, _ := vpp.RunCli("show capo int")
			fmt.Printf(st)
		})
		It("should configure empty host endpoint", func() {
			// this should change as we fix the behaviour of an empty host endpoint (deny)
			cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should create an empty host endpoint")
			err := cmd.Start()
			Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
			_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
			Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("invertedaddr=10.0.100.0]\n["))
			st, _ := vpp.RunCli("show capo int")
			fmt.Printf(st)
		})
		Context("with a policy not applied on forward", func() {
			JustBeforeEach(func() {
				cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should create a host endpoint with a policy not on forward")
				err := cmd.Start()
				Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
				_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
			})
			It("should configure host endpoint with policy not applied on forward", func() {
				// uplink should be empty
				Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("invertedaddr=10.0.100.0]\n["))
				// vpptap should have policy applied
				Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("1.9.9.1"))
				st, _ := vpp.RunCli("show capo int")
				fmt.Printf(st)
			})
			It("should configure failsafe policies", func() {
				Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("rx:[rule#8;allow][proto==TCP,dst==179,dst==2379,dst==2380,dst==5473,dst==6443,dst==6666,dst==6667,]"))
				st, _ := vpp.RunCli("show capo int")
				fmt.Printf(st)
			})
		})
		It("should configure host endpoint with policy and apply on forward", func() {
			cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should create a host endpoint with a policy on forward")
			err := cmd.Start()
			Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
			_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
			Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("1.9.9.1"))
			st, _ := vpp.RunCli("show capo int")
			fmt.Printf(st)
		})
		It("should configure wildcard host endpoint", func() {
			cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should create a wildcard host endpoint")
			err := cmd.Start()
			Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
			_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
			Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("[tap0 sw_if_index=1 invertedaddr=10.0.100.0]"))
			st, _ := vpp.RunCli("show capo int")
			fmt.Printf(st)
		})
	})
	/*Describe("Felix Configuration functionalities", func() {
		It("should change default endpoint to host action", func() {
			cmd.Env = append(cmd.Env, "GINKGO_FOCUS=should change default endpoint to host action to ACCEPT")
			err := cmd.Start()
			Expect(err).Should(BeNil(), "Failed to start felix %+v", err)
			_ = watchDog.Wait(policyServer.FelixConfigChan, "Waiting for FelixConfig to be provided by the calico pod")
			Eventually(vpp.RunCli, testTimeout).WithArguments("show capo int").Should(ContainSubstring("tx:[rule#0;allow][src==[ipset#0;ip;],]"))
			st, _ := vpp.RunCli("show capo int")
			fmt.Printf(st)
		})
	})*/
	AfterEach(func() {
		//cmd.Process.Kill()
		//syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		//log.Info(cmd.Process.Pid)
		test.TeardownVPP()
		test.TeardownPod()
	})
})

func Go(f func(t *tomb.Tomb) error) {
	t.Go(func() error {
		defer GinkgoRecover()
		err := f(&t)
		if err != nil {
			Expect(err).Should(BeNil(), "Tomb function errored with %s", err)
		}
		return err
	})
}
