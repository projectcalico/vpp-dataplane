package main_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cni", func() {
	var log *logrus.Logger
	var vpp *vpplink.VppLink
	var err error
	var ipAddress string
	log = logrus.New()
	var vppCmd *exec.Cmd

	arg := os.Args //(1:namespace) (2:pod name) (3:interface type) (4:interface name) (5:network prefix)
	var vppBinary string
	if len(arg) < 2 {
		vppBinary = "/usr/bin/vpp"
	} else {
		vppBinary = arg[1]
	}

	if ns.IsNSorErr("/run/netns/vpptest") != nil {
		netns.NewNamed("vpptest")
	}

	err = ns.WithNetNSPath("/run/netns/vpptest", func(ns.NetNS) (err error) {
		vppCmd = exec.Command(vppBinary, `unix {
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
		  }`)
		vppCmd.Stdout = os.Stdout
		vppCmd.Stderr = os.Stderr
		err = vppCmd.Start()
		if err != nil {
			return err
		}
		//vppProcess = vppCmd.Process
		return nil
	})
	if err != nil {
		log.Fatalf("Error starting vpp process %+v", err)
	}

	vpp, err = common.CreateVppLink("/var/run/vpp/vpp-api-test.sock", log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Fatalf("Cannot create VPP client: %v", err)
	}
	Expect(vpp).NotTo(BeNil())
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
	ipam := watchers.NewIPAMCache(vpp, nil, log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
	cniServer := cni.NewCNIServer(vpp, ipam, log.WithFields(logrus.Fields{"component": "cni"}))
	cniServer.SetFelixConfig(&config.Config{})
	common.InitRestartHandler()
	common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))

	BeforeEach(func() {
		ipAddress = "1.2.3.44"
		if ns.IsNSorErr("/run/netns/pod-test") != nil {
			netns.NewNamed("pod-test")
		}
		newPod := &proto.AddRequest{
			InterfaceName: "newInterface",
			Netns:         "/run/netns/pod-test",
			ContainerIps:  []*proto.IPConfig{{Address: ipAddress+"/24"}},
			Workload:      &proto.WorkloadIDs{},
		}
		ipam.ForceReady()
		cniServer.Add(context.Background(), newPod)
		log.Infof("done adding pod")
	})

	Describe("Cni server", func() {
		Context("context", func() {
			It("should have interface in linux and vpp", func() {
				var rightAdressInLinux bool
				err = ns.WithNetNSPath("/run/netns/pod-test", func(ns.NetNS) error {
					link, err := netlink.LinkByName("newInterface")
					if err != nil {
						return errors.Wrapf(err, "unable to retrieve name")
					}
					addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
					if err != nil {
						return errors.Wrapf(err, "unable to retrieve address")
					}
					for _, addr := range addresses {
						if addr.IP.Equal(net.ParseIP(ipAddress)) {
							rightAdressInLinux = true
						}
					}
					return nil
				})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(rightAdressInLinux).To(BeTrue())
				log.Infof("checked eth0 interface in linux with address in pool")
				var ifSwIfIndex uint32
				ifSwIfIndex, err = vpp.SearchInterfaceWithTag("tun-/run/netns/pod-test-newInterface") //is tag truncated?
				Expect(err).ShouldNot(HaveOccurred())
				Expect(ifSwIfIndex).NotTo(BeZero())
				couple, err := vpp.InterfaceGetUnnumbered(ifSwIfIndex)
				if err != nil {
					log.Error(err)
				}
				Expect(err).ShouldNot(HaveOccurred())
				lb := uint32(couple.IPSwIfIndex)
				addrList, err := vpp.AddrList(lb, false)
				if err != nil {
					log.Error(err)
				}
				Expect(err).ShouldNot(HaveOccurred())
				var correctAdress bool
				for _, addr := range addrList {
					if addr.IPNet.IP.Equal(net.ParseIP(ipAddress)) {
						correctAdress = true
					}
				}
				Expect(correctAdress).To(BeTrue())
				log.Infof("checked tun in vpp with eth0 address")
				b, err := vpp.GetInterfaceDetails(ifSwIfIndex)
				if err != nil {
					log.Error(err)
				}
				Expect(err).ShouldNot(HaveOccurred())
				Expect(int(b.Mtu[0])).To(Equal(vpplink.MAX_MTU))
				log.Infof("checked right mtu")
			})
		})
	})

	AfterEach(func() {
		newPod := &proto.DelRequest{
			InterfaceName: "newInterface",
			Netns:         "/run/netns/pod-test",
		}
		cniServer.Del(context.Background(), newPod)
		log.Infof("done deleting pod")
		if err := vppCmd.Process.Kill(); err != nil {
			log.Fatal("failed to kill process: ", err)
		}
		log.Infof("%+v", vppCmd.Process.Pid)
		netns.DeleteNamed("pod-test")
		netns.DeleteNamed("vpptest")
	})
})
