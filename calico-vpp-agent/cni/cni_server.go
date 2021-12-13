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
	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	tomb "gopkg.in/tomb.v2"
)

type Server struct {
	*common.CalicoVppServerData
	log *logrus.Entry
	vpp *vpplink.VppLink

	ipam watchers.IpamCache

	grpcServer *grpc.Server

	podInterfaceMap map[string]storage.LocalPodSpec
	lock            sync.Mutex /* protects Add/DelVppInterace/OnVppRestart/RescanState */

	memifDriver    *pod_interface.MemifPodInterfaceDriver
	tuntapDriver   *pod_interface.TunTapPodInterfaceDriver
	vclDriver      *pod_interface.VclPodInterfaceDriver
	loopbackDriver *pod_interface.LoopbackPodInterfaceDriver

	availableBuffers uint64
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
		HostPorts:      make([]storage.HostPortBinding, 0),

		/* defaults */
		MemifIsL3:  false,
		TunTapIsL3: true,

		MemifSwIfIndex:  vpplink.InvalidID,
		TunTapSwIfIndex: vpplink.InvalidID,
	}

	for _, port := range request.Workload.Ports {
		podSpec.HostPorts = append(podSpec.HostPorts, storage.HostPortBinding{
			HostPort:      port.HostPort,
			HostIP:        net.ParseIP(port.HostIp),
			ContainerPort: port.Port,
		})

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

	common.WaitIfVppIsRestarting()
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("Adding Pod %s", podSpec.String())

	swIfIndex, err := s.AddVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
		s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err)
		return &pb.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PodAdded,
		New:  podSpec,
	})

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
	availableBuffers, _, _, err := s.vpp.GetBufferStats()
	if err != nil {
		s.log.WithError(err).Errorf("could not get available buffers")
	}
	s.availableBuffers = uint64(availableBuffers)

	s.FetchNDataThreads()

	if config.VCLEnabled {
		err := s.vclDriver.Init()
		if err != nil {
			s.log.Errorf("Error initializing VCL %v", err)
			return err
		}
	}

	podSpecs, err := storage.LoadCniServerState(config.CniServerStateFile)
	if err != nil {
		s.log.Errorf("Error getting pods %v", err)
		return err
	}

	s.log.Infof("RescanState: re-creating all interfaces")
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, podSpec := range podSpecs {
		_, err2 := s.AddVppInterface(&podSpec, false /* doHostSideConf */)
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
	if config.VCLEnabled {
		err := s.vclDriver.Init()
		if err != nil {
			s.log.Errorf("Error initializing VCL %v", err)
		}
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	for name, podSpec := range s.podInterfaceMap {
		_, err := s.AddVppInterface(&podSpec, false /* doHostSideConf */)
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
	common.WaitIfVppIsRestarting()
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("Deleting pod %s", partialPodSpec.Key())
	initialSpec, ok := s.podInterfaceMap[partialPodSpec.Key()]
	if !ok {
		s.log.Warnf("Unknown pod to delete")
	} else {
		s.log.Infof("Deleting pod %s", initialSpec.String())
		s.DelVppInterface(&initialSpec)
		s.log.Infof("Done Deleting pod %s", initialSpec.String())
	}

	delete(s.podInterfaceMap, initialSpec.Key())
	err := storage.PersistCniServerState(s.podInterfaceMap, config.CniServerStateFile)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}

	common.SendEvent(common.CalicoVppEvent{
		Type: common.PodDeleted,
		Old:  &initialSpec,
	})

	return &pb.DelReply{
		Successful: true,
	}, nil
}

// Serve runs the grpc server for the Calico CNI backend API
func NewCNIServer(vpp *vpplink.VppLink, ipam watchers.IpamCache, log *logrus.Entry) *Server {
	server := &Server{
		vpp: vpp,
		log: log,

		ipam: ipam,

		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]storage.LocalPodSpec),
		tuntapDriver:    pod_interface.NewTunTapPodInterfaceDriver(vpp, log),
		memifDriver:     pod_interface.NewMemifPodInterfaceDriver(vpp, log),
		vclDriver:       pod_interface.NewVclPodInterfaceDriver(vpp, log),
		loopbackDriver:  pod_interface.NewLoopbackPodInterfaceDriver(vpp, log),
	}
	return server
}

func (s *Server) ServeCNI(t *tomb.Tomb) error {
	syscall.Unlink(config.CNIServerSocket)
	socketListener, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on %s", config.CNIServerSocket)
	}

	pb.RegisterCniDataplaneServer(s.grpcServer, s)
	s.rescanState()

	s.log.Infof("Serve() CNI")
	go s.grpcServer.Serve(socketListener)

	<-t.Dying()

	s.log.Infof("CNI Server returned")

	s.grpcServer.GracefulStop()
	syscall.Unlink(config.CNIServerSocket)
	return nil
}
