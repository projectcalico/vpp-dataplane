package main_test

import (
	//"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"

	//calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	//"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"

	//"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	//"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cni", func() {
	var linuxAddr net.IP
	var log *logrus.Logger
	var vpp *vpplink.VppLink
	var err error
	var podSpec *storage.LocalPodSpec
	arg := os.Args //1:namespace 2:pod name 3:interface type

	BeforeEach(func() {
		log = logrus.New()
		vpp, err = common.CreateVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
		if err != nil {
			log.Fatalf("Cannot create VPP client: %v", err)
		}
		Expect(vpp).NotTo(BeNil())

		cniServerStateFile := fmt.Sprintf("%s%d", config.CniServerStateFile, storage.CniServerStateFileVersion)
		podSpecs, err := storage.LoadCniServerState(cniServerStateFile)
		Expect(err).ShouldNot(HaveOccurred())
		for _, existingPodSpec := range podSpecs {
			if existingPodSpec.WorkloadID == arg[1]+"/"+arg[2] {
				podSpec = &existingPodSpec
				break
			}
		}
		Expect(podSpec).NotTo(BeNil())
		/*clientv3, err := calicov3cli.NewFromEnv()
		if err != nil {
			log.Fatalf("cannot create calico v3 api client %s", err)
		}
		ipam := watchers.NewIPAMCache(vpp, clientv3, log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}))
		cniServer := cni.NewCNIServer(vpp, ipam, log.WithFields(logrus.Fields{"component": "cni"}))
		config.CNIServerSocket = "/var/run/calico/cni-server-test.sock"
		go cniServer.ServeCNI(nil)
		cniServer.Add(context.Background(), &proto.AddRequest{InterfaceName:"new"})*/

	})

	Describe("Create samplepod", func() {
		Context("just a pod in the main network", func() {
			It("should have eth0 interface in linux with address in pool", func() {

				err = ns.WithNetNSPath(podSpec.NetnsName, func(ns.NetNS) error {
					link, err := netlink.LinkByName("eth0")
					if err != nil {
						return errors.Wrapf(err, "unable to retrieve name")
					}
					addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
					if err != nil {
						return errors.Wrapf(err, "unable to retrieve address")
					}
					for _, addr := range addresses {
						linuxAddr = addr.IP
						break
					}
					return nil
				})
				Expect(err).ShouldNot(HaveOccurred())

				inPool := strings.HasPrefix(linuxAddr.String(), "172.16.")
				Expect(inPool).To(BeTrue())
			})

			Context("Should have tun in vpp with eth0 address and right mtu", func() {
				var allInterfaces map[string]uint32

				BeforeEach(func() {
					allInterfaces, err = vpp.SearchInterfacesWithTagPrefix(arg[3] + "-" + podSpec.NetnsName) //is tag truncated?
					Expect(err).ShouldNot(HaveOccurred())
					Expect(allInterfaces).NotTo(BeEmpty())
				})

				It("Should have tun in vpp with eth0 address", func() {
					for _, swifindex := range allInterfaces {
						couple, err := vpp.InterfaceGetUnnumbered(swifindex)
						Expect(err).ShouldNot(HaveOccurred())

						lb := uint32(couple.IPSwIfIndex)
						addrList, err := vpp.AddrList(lb, false)
						Expect(err).ShouldNot(HaveOccurred())

						var correctAdress bool
						for _, addr := range addrList {
							if addr.IPNet.IP.Equal(linuxAddr) {
								correctAdress = true
							}
						}
						Expect(correctAdress).To(BeTrue())
						break
					}
				})

				It("Should have right MTU", func() {
					for _, swifindex := range allInterfaces {
						b, err := vpp.GetInterfaceDetails(swifindex)
						Expect(err).ShouldNot(HaveOccurred())

						Expect(int(b.Mtu[0])).To(Equal(vpplink.MAX_MTU))
						break
					}
				})
			})
		})

	})
})
