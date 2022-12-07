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

package cni

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/pod_interface"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	config "github.com/projectcalico/vpp-dataplane/config/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type Server struct {
	log *logrus.Entry
	vpp *vpplink.VppLink

	policyServerIpam common.PolicyServerIpam

	grpcServer *grpc.Server

	podInterfaceMap map[string]storage.LocalPodSpec
	lock            sync.Mutex /* protects Add/DelVppInterace/RescanState */
	cniEventChan    chan common.CalicoVppEvent

	memifDriver    *pod_interface.MemifPodInterfaceDriver
	tuntapDriver   *pod_interface.TunTapPodInterfaceDriver
	vclDriver      *pod_interface.VclPodInterfaceDriver
	loopbackDriver *pod_interface.LoopbackPodInterfaceDriver

	availableBuffers uint64

	networkDefinitions   map[string]*watchers.NetworkDefinition
	cniMultinetEventChan chan common.CalicoVppEvent
	multinetLock         sync.Mutex
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
}

func getHostEndpointProto(proto string) types.IPProto {
	switch proto {
	case "udp":
		return types.UDP
	case "sctp":
		return types.SCTP
	case "tcp":
		return types.TCP
	default:
		return types.TCP
	}
}

func (s *Server) SetFelixConfig(felixConfig *felixConfig.Config) {
	s.tuntapDriver.SetFelixConfig(felixConfig)
}

func (s *Server) newLocalPodSpecFromAdd(request *pb.AddRequest) (*storage.LocalPodSpec, error) {
	podSpec := storage.LocalPodSpec{
		InterfaceName:     request.GetInterfaceName(),
		NetnsName:         request.GetNetns(),
		AllowIpForwarding: request.GetSettings().GetAllowIpForwarding(),
		Routes:            make([]storage.LocalIPNet, 0),
		ContainerIps:      make([]storage.LocalIP, 0),
		Mtu:               int(request.GetSettings().GetMtu()),

		IfPortConfigs: make([]storage.LocalIfPortConfigs, 0),

		OrchestratorID: request.Workload.Orchestrator,
		WorkloadID:     request.Workload.Namespace + "/" + request.Workload.Pod,
		EndpointID:     request.Workload.Endpoint,
		HostPorts:      make([]storage.HostPortBinding, 0),

		/* defaults */
		IfSpec:       GetDefaultIfSpec(true /* isL3 */),
		PBLMemifSpec: GetDefaultIfSpec(false /* isL3 */),

		V4VrfId: vpplink.InvalidID,
		V6VrfId: vpplink.InvalidID,

		MemifSwIfIndex:  vpplink.InvalidID,
		TunTapSwIfIndex: vpplink.InvalidID,

		NetworkName: request.DataplaneOptions["network_name"],
	}

	if podSpec.NetworkName != "" {
		if !config.MultinetEnabled {
			return nil, fmt.Errorf("enable multinet in config for multiple networks")
		}
		if isMemif(podSpec.InterfaceName) {
			if !config.MemifEnabled {
				return nil, fmt.Errorf("enable memif in config for memif interfaces")
			}
			podSpec.EnableMemif = true
			podSpec.DefaultIfType = storage.VppIfTypeMemif
			podSpec.IfSpec = GetDefaultIfSpec(false)
		}
	}

	for _, port := range request.Workload.Ports {
		hostIP := net.ParseIP(port.HostIp)
		hostPort := uint16(port.HostPort)
		if hostPort != 0 && hostIP != nil && !hostIP.IsUnspecified() {
			podSpec.HostPorts = append(podSpec.HostPorts, storage.HostPortBinding{
				HostPort:      hostPort,
				HostIP:        hostIP,
				ContainerPort: uint16(port.Port),
				Protocol:      getHostEndpointProto(port.Protocol),
			})
		}
	}
	for _, routeStr := range request.GetContainerRoutes() {
		_, route, err := net.ParseCIDR(routeStr)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse container route %s", routeStr)
		}
		podSpec.Routes = append(podSpec.Routes, storage.LocalIPNet{
			IP:   route.IP,
			Mask: route.Mask,
		})
	}
	s.multinetLock.Lock()
	if podSpec.NetworkName != "" {
		_, route, err := net.ParseCIDR(s.networkDefinitions[podSpec.NetworkName].Range)
		if err == nil {
			podSpec.Routes = append(podSpec.Routes, storage.LocalIPNet{
				IP:   route.IP,
				Mask: route.Mask,
			})
		}
	}
	s.multinetLock.Unlock()
	for _, requestContainerIP := range request.GetContainerIps() {
		containerIp, _, err := net.ParseCIDR(requestContainerIP.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("Cannot parse address: %s", requestContainerIP.GetAddress())
		}
		// We ignore the prefix len set on the address,
		// for a tun it doesn't make sense
		podSpec.ContainerIps = append(podSpec.ContainerIps, storage.LocalIP{IP: containerIp})
	}
	workload := request.GetWorkload()
	if workload != nil {
		err := s.ParsePodAnnotations(&podSpec, workload.Annotations)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse pod Annotations")
		}
	}

	if podSpec.DefaultIfType == storage.VppIfTypeUnknown {
		podSpec.DefaultIfType = storage.VppIfTypeTunTap
	}

	return &podSpec, nil
}

func NewLocalPodSpecFromDel(request *pb.DelRequest) *storage.LocalPodSpec {
	return &storage.LocalPodSpec{
		InterfaceName: request.GetInterfaceName(),
		NetnsName:     request.GetNetns(),
	}
}

func (s *Server) Add(ctx context.Context, request *pb.AddRequest) (*pb.AddReply, error) {
	/* We don't support request.GetDesiredHostInterfaceName() */
	podSpec, err := s.newLocalPodSpecFromAdd(request)
	if err != nil {
		s.log.Errorf("Error parsing interface add request %v %v", request, err)
		return &pb.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	if podSpec.NetnsName == "" {
		s.log.Debugf("no netns passed, skipping")
		return &pb.AddReply{
			Successful: true,
		}, nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("pod(add) spec=%s network=%s", podSpec.String(), request.DataplaneOptions["network_name"])

	existingSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if ok {
		s.log.Info("pod(add) found existing spec")
		podSpec = &existingSpec
	}

	swIfIndex, err := s.AddVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
		s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err)
		return &pb.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}

	s.podInterfaceMap[podSpec.Key()] = *podSpec
	cniServerStateFile := fmt.Sprintf("%s%d", config.CniServerStateFile, storage.CniServerStateFileVersion)
	err = storage.PersistCniServerState(s.podInterfaceMap, cniServerStateFile)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
	s.log.Infof("pod(add) Done spec=%s", podSpec.String())
	// XXX: container MAC doesn't make sense with tun, we just pass back a constant one.
	// How does calico / k8s use it?
	// TODO: pass real mac for tap ?
	return &pb.AddReply{
		Successful:        true,
		HostInterfaceName: swIfIdxToIfName(swIfIndex),
		ContainerMac:      "02:00:00:00:00:00",
	}, nil
}

func (s *Server) fetchNDataThreads() {
	nDataThreads := common.FetchNDataThreads(s.vpp, s.log)
	s.memifDriver.NDataThreads = nDataThreads
	s.tuntapDriver.NDataThreads = nDataThreads
}

func (s *Server) FetchBufferConfig() {
	availableBuffers, _, _, err := s.vpp.GetBufferStats()
	if err != nil {
		s.log.WithError(err).Errorf("could not get available buffers")
	}
	s.availableBuffers = uint64(availableBuffers)
}

func (s *Server) rescanState() {
	s.FetchBufferConfig()
	s.fetchNDataThreads()

	if config.VCLEnabled {
		err := s.vclDriver.Init()
		if err != nil {
			/* it might already be enabled, do not return */
			s.log.Errorf("Error initializing VCL %v", err)
		}
	}

	cniServerStateFile := fmt.Sprintf("%s%d", config.CniServerStateFile, storage.CniServerStateFileVersion)
	podSpecs, err := storage.LoadCniServerState(cniServerStateFile)
	if err != nil {
		s.log.Errorf("Error getting pods from file %s, removing cache", err)
		err := os.Remove(cniServerStateFile)
		if err != nil {
			s.log.Errorf("Could not remove %s, %s", cniServerStateFile, err)
		}
	}

	s.log.Infof("RescanState: re-creating all interfaces")
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, podSpec := range podSpecs {
		/* copy podSpec as a pointer to it will be sent over the event chan */
		podSpecCopy := podSpec.Copy()
		_, err := s.AddVppInterface(&podSpecCopy, false /* doHostSideConf */)
		switch err.(type) {
		case PodNSNotFoundErr:
			s.log.Infof("Interface restore but netns missing %s", podSpecCopy.String())
		case nil:
			s.log.Infof("pod(re-add) podSpec=%s", podSpecCopy.String())
			s.podInterfaceMap[podSpec.Key()] = podSpecCopy
		default:
			s.log.Errorf("Interface add failed %s : %v", podSpecCopy.String(), err)
		}
	}
}

func (s *Server) Del(ctx context.Context, request *pb.DelRequest) (*pb.DelReply, error) {
	partialPodSpec := NewLocalPodSpecFromDel(request)
	// Only try to delete the device if a namespace was passed in.
	if partialPodSpec.NetnsName == "" {
		s.log.Debugf("no netns passed, skipping")
		return &pb.DelReply{
			Successful: true,
		}, nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("pod(del) key=%s", partialPodSpec.Key())
	initialSpec, ok := s.podInterfaceMap[partialPodSpec.Key()]
	if !ok {
		s.log.Warnf("Unknown pod to delete key=%s", partialPodSpec.Key())
	} else {
		s.log.Infof("pod(del) spec=%s", initialSpec.String())
		s.DelVppInterface(&initialSpec)
		s.log.Infof("pod(del) Done! spec=%s", initialSpec.String())
	}

	delete(s.podInterfaceMap, initialSpec.Key())
	err := storage.PersistCniServerState(s.podInterfaceMap, config.CniServerStateFile+fmt.Sprint(storage.CniServerStateFileVersion))
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}

	return &pb.DelReply{
		Successful: true,
	}, nil
}

// Serve runs the grpc server for the Calico CNI backend API
func NewCNIServer(vpp *vpplink.VppLink, policyServerIpam common.PolicyServerIpam, log *logrus.Entry) *Server {
	server := &Server{
		vpp: vpp,
		log: log,

		policyServerIpam: policyServerIpam,
		cniEventChan:     make(chan common.CalicoVppEvent, common.ChanSize),

		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]storage.LocalPodSpec),
		tuntapDriver:    pod_interface.NewTunTapPodInterfaceDriver(vpp, log),
		memifDriver:     pod_interface.NewMemifPodInterfaceDriver(vpp, log),
		vclDriver:       pod_interface.NewVclPodInterfaceDriver(vpp, log),
		loopbackDriver:  pod_interface.NewLoopbackPodInterfaceDriver(vpp, log),

		networkDefinitions:   make(map[string]*watchers.NetworkDefinition),
		cniMultinetEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
	}
	reg := common.RegisterHandler(server.cniEventChan, "CNI server events")
	reg.ExpectEvents(
		common.FelixConfChanged,
		common.IpamConfChanged,
	)
	regM := common.RegisterHandler(server.cniMultinetEventChan, "CNI server Multinet events")
	regM.ExpectEvents(
		common.NetAddedOrUpdated,
		common.NetDeleted,
		common.NetsSynced,
	)
	return server
}
func (s *Server) cniServerEventLoop(t *tomb.Tomb) error {
	for {
		select {
		case <-t.Dying():
			break
		case evt := <-s.cniEventChan:
			switch evt.Type {
			case common.FelixConfChanged:
				if new, _ := evt.New.(*felixConfig.Config); new != nil {
					s.lock.Lock()
					s.tuntapDriver.FelixConfigChanged(new, 0 /* ipipEncapRefCountDelta */, 0 /* vxlanEncapRefCountDelta */, s.podInterfaceMap)
					s.lock.Unlock()
				}
			case common.IpamConfChanged:
				old, _ := evt.Old.(*proto.IPAMPool)
				new, _ := evt.New.(*proto.IPAMPool)
				ipipEncapRefCountDelta := 0
				vxlanEncapRefCountDelta := 0
				if old != nil && calicov3.VXLANMode(old.VxlanMode) != calicov3.VXLANModeNever {
					vxlanEncapRefCountDelta--
				}
				if old != nil && calicov3.IPIPMode(old.IpipMode) != calicov3.IPIPModeNever {
					ipipEncapRefCountDelta--
				}
				if new != nil && calicov3.VXLANMode(new.VxlanMode) != calicov3.VXLANModeNever {
					vxlanEncapRefCountDelta++
				}
				if new != nil && calicov3.IPIPMode(new.IpipMode) != calicov3.IPIPModeNever {
					ipipEncapRefCountDelta++
				}

				for _, podSpec := range s.podInterfaceMap {
					NeededSnat := podSpec.NeedsSnat
					for _, containerIP := range podSpec.GetContainerIps() {
						podSpec.NeedsSnat = podSpec.NeedsSnat || s.policyServerIpam.IPNetNeedsSNAT(containerIP)
					}
					if NeededSnat != podSpec.NeedsSnat {
						for _, swIfIndex := range []uint32{podSpec.LoopbackSwIfIndex, podSpec.TunTapSwIfIndex, podSpec.MemifSwIfIndex} {
							if swIfIndex != vpplink.InvalidID {
								s.log.Infof("Enable/Disable interface[%d] SNAT", swIfIndex)
								for _, ipFamily := range vpplink.IpFamilies {
									err := s.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIp6, podSpec.NeedsSnat)
									if err != nil {
										return errors.Wrapf(err, "Error enabling/disabling %s snat", ipFamily.Str)
									}
								}
							}
						}
					}
				}
				s.lock.Lock()
				s.tuntapDriver.FelixConfigChanged(nil /* felixConfig */, ipipEncapRefCountDelta, vxlanEncapRefCountDelta, s.podInterfaceMap)
				s.lock.Unlock()
			}
		}
	}
}

func (s *Server) ServeCNI(t *tomb.Tomb) error {
	err := syscall.Unlink(config.CNIServerSocket)
	if err != nil {
		return err
	}
	socketListener, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on %s", config.CNIServerSocket)
	}

	pb.RegisterCniDataplaneServer(s.grpcServer, s)

	if config.MultinetEnabled {
		netsSynced := make(chan bool)
		go func() {
			for {
				select {
				case <-t.Dying():
					return
				case event := <-s.cniMultinetEventChan:
					switch event.Type {
					case common.NetsSynced:
						netsSynced <- true
					case common.NetAddedOrUpdated:
						netDef := event.New.(*watchers.NetworkDefinition)
						s.multinetLock.Lock()
						s.networkDefinitions[netDef.Name] = netDef
						s.multinetLock.Unlock()
					case common.NetDeleted:
						netDef := event.Old.(*watchers.NetworkDefinition)
						s.multinetLock.Lock()
						delete(s.networkDefinitions, netDef.Name)
						s.multinetLock.Unlock()
					}
				}
			}
		}()
		<-netsSynced
		s.log.Infof("Networks synced")
	}
	s.rescanState()

	s.log.Infof("Serve() CNI")

	go func() {
		err := s.grpcServer.Serve(socketListener)
		if err != nil {
			s.log.Fatalf("GrpcServer Server returned %s", err)
		}
	}()

	err = s.cniServerEventLoop(t)
	if err != nil {
		return err
	}

	s.log.Infof("CNI Server returned")

	s.grpcServer.GracefulStop()
	err = syscall.Unlink(config.CNIServerSocket)
	if err != nil {
		return err
	}

	return nil
}

// ForceAddingNetworkDefinition will add another NetworkDefinition to this CNI server.
// The usage is mainly for testing purposes.
func (s *Server) ForceAddingNetworkDefinition(networkDefinition *watchers.NetworkDefinition) {
	s.networkDefinitions[networkDefinition.Name] = networkDefinition
}
