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
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/pod_interface"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy"
	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Server struct {
	*common.CalicoVppServerData
	log             *logrus.Entry
	vpp             *vpplink.VppLink
	grpcServer      *grpc.Server
	client          *kubernetes.Clientset
	socketListener  net.Listener
	routingServer   *routing.Server
	policyServer    *policy.Server
	podInterfaceMap map[string]storage.LocalPodSpec
	/* without main thread */
	lock           sync.Mutex
	memifDriver    *pod_interface.MemifPodInterfaceDriver
	tuntapDriver   *pod_interface.TunTapPodInterfaceDriver
	vclDriver      *pod_interface.VclPodInterfaceDriver
	loopbackDriver *pod_interface.LoopbackPodInterfaceDriver

	indexAllocator *vpplink.IndexAllocator
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
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

		/* defaults */
		MemifIsL3:  false,
		TunTapIsL3: true,

		MemifSwIfIndex:  vpplink.InvalidID,
		TunTapSwIfIndex: vpplink.InvalidID,
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

	s.BarrierSync()
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("Adding Pod %s", podSpec.String())
	podSpec.VrfId = s.indexAllocator.AllocateIndex()
	s.log.Infof("Allocated VrfId:%d", podSpec.VrfId)

	swIfIndex, err := s.AddVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
		s.indexAllocator.FreeIndex(podSpec.VrfId)
		s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err)
		return &pb.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}

	s.podInterfaceMap[podSpec.Key()] = *podSpec
	err = storage.PersistCniServerState(s.podInterfaceMap, config.CniServerStateFile)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
	s.log.Infof("Done Adding Pod %s", podSpec.String())
	// XXX: container MAC doesn't make sense anymore, we just pass back a constant one.
	// How does calico / k8s use it?
	return &pb.AddReply{
		Successful:        true,
		HostInterfaceName: swIfIdxToIfName(swIfIndex),
		ContainerMac:      "02:00:00:00:00:00",
	}, nil
}

func (p *Server) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	return p.routingServer.IPNetNeedsSNAT(prefix)
}

func (s *Server) FetchNDataThreads() {
	nVppWorkers, err := s.vpp.GetNumVPPWorkers()
	if err != nil {
		s.log.Panicf("Error getting number of VPP workers: %v", err)
	}
	nDataThreads := nVppWorkers
	if config.IpsecNbAsyncCryptoThread > 0 {
		nDataThreads = nVppWorkers - config.IpsecNbAsyncCryptoThread
		if nDataThreads <= 0 {
			s.log.Error("Couldn't fullfill request [crypto=%d total=%d]", config.IpsecNbAsyncCryptoThread, nVppWorkers)
			nDataThreads = nVppWorkers
		}
		s.log.Info("Using [data=%d crypto=%d]", nDataThreads, nVppWorkers-nDataThreads)

	}
	s.memifDriver.NDataThreads = nDataThreads
	s.tuntapDriver.NDataThreads = nDataThreads
}

func (s *Server) rescanState() error {
	s.FetchNDataThreads()

	podSpecs, err := storage.LoadCniServerState(config.CniServerStateFile)
	if err != nil {
		s.log.Errorf("Error getting pods %v", err)
		return err
	}

	s.log.Infof("RescanState: re-creating all interfaces")
	for _, podSpec := range podSpecs {
		err2 := s.indexAllocator.TakeIndex(podSpec.VrfId)
		if err2 != nil {
			s.log.Errorf("Error Taking back index %d : %v", podSpec.VrfId, err2)
			continue
		}
		_, err2 = s.AddVppInterface(&podSpec, false /* doHostSideConf */)
		if err2 != nil {
			// TODO: some errors are probably not critical, for instance if the interface
			// can't be created because the netns disappeared (may happen when the host reboots)
			s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err2)
			err = err2
		} else {
			s.podInterfaceMap[podSpec.Key()] = podSpec
		}
	}
	return err
}

func (s *Server) OnVppRestart() {
	s.log.Infof("VppRestart: re-creating all interfaces")
	for name, podSpec := range s.podInterfaceMap {
		err := s.indexAllocator.TakeIndex(podSpec.VrfId)
		if err != nil {
			s.log.Errorf("Error Taking back index %d : %v", podSpec.VrfId, err)
			continue
		}
		_, err = s.AddVppInterface(&podSpec, false /* doHostSideConf */)
		if err != nil {
			s.log.Errorf("Error re-injecting interface %s : %v", name, err)
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
	s.BarrierSync()
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("Deleting pod %s", partialPodSpec.Key())
	initialSpec, ok := s.podInterfaceMap[partialPodSpec.Key()]
	if !ok {
		s.log.Warnf("Unknown pod to delete")
	} else {
		s.policyServer.WorkloadRemoved(&policy.WorkloadEndpointID{
			OrchestratorID: initialSpec.OrchestratorID,
			WorkloadID:     initialSpec.WorkloadID,
			EndpointID:     initialSpec.EndpointID,
		})
		s.log.Infof("Deleting pod %s", initialSpec.String())
		s.DelVppInterface(&initialSpec)
		s.log.Infof("Freeing VRF Index %d", initialSpec.VrfId)
		s.indexAllocator.FreeIndex(initialSpec.VrfId)
		s.log.Infof("Done Deleting pod %s", initialSpec.String())
	}

	delete(s.podInterfaceMap, initialSpec.Key())
	err := storage.PersistCniServerState(s.podInterfaceMap, config.CniServerStateFile)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
	return &pb.DelReply{
		Successful: true,
	}, nil
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
	syscall.Unlink(config.CNIServerSocket)
}

// Serve runs the grpc server for the Calico CNI backend API
func NewServer(v *vpplink.VppLink, rs *routing.Server, ps *policy.Server, l *logrus.Entry) (*Server, error) {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		panic(err.Error())
	}
	syscall.Unlink(config.CNIServerSocket)
	lis, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		l.Fatalf("failed to listen on %s: %v", config.CNIServerSocket, err)
		return nil, err
	}

	server := &Server{
		vpp:             v,
		log:             l,
		routingServer:   rs,
		policyServer:    ps,
		socketListener:  lis,
		client:          client,
		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]storage.LocalPodSpec),
		tuntapDriver:    pod_interface.NewTunTapPodInterfaceDriver(v, l),
		memifDriver:     pod_interface.NewMemifPodInterfaceDriver(v, l),
		vclDriver:       pod_interface.NewVclPodInterfaceDriver(v, l),
		loopbackDriver:  pod_interface.NewLoopbackPodInterfaceDriver(v, l),
		indexAllocator:  vpplink.NewIndexAllocator(common.PerPodVRFIndexStart),
	}
	pb.RegisterCniDataplaneServer(server.grpcServer, server)
	l.Infof("Server starting")
	return server, nil
}

func (s *Server) Serve() {
	s.rescanState()
	s.log.Infof("Serve() CNI")
	err := s.grpcServer.Serve(s.socketListener)
	if err != nil {
		s.log.Fatalf("Failed to serve: %v", err)
	}
}
