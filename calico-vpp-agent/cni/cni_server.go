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
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
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
	NumVPPWorkers int
	lock          sync.Mutex
	vppLinuxMtu   int
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
}

func fetchVppLinuxMtu() (mtu int, err error) {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerLinuxMtu)
		if err == nil {
			idx, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 32)
			if err == nil && idx != -1 {
				return int(idx), nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return 0, errors.Errorf("Vpp-host mtu not ready after 20 tries")
}

func NewLocalPodSpecFromAdd(request *pb.AddRequest) (*storage.LocalPodSpec, error) {
	podSpec := storage.LocalPodSpec{
		InterfaceName:     request.GetInterfaceName(),
		NetnsName:         request.GetNetns(),
		AllowIpForwarding: request.GetSettings().GetAllowIpForwarding(),
		Routes:            make([]storage.LocalIPNet, 0),
		ContainerIps:      make([]storage.LocalIP, 0),

		OrchestratorID: request.Workload.Orchestrator,
		WorkloadID:     request.Workload.Namespace + "/" + request.Workload.Pod,
		EndpointID:     request.Workload.Endpoint,
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

	return &podSpec, nil
}

func NewLocalPodSpecFromDel(request *pb.DelRequest) *storage.LocalPodSpec {
	return &storage.LocalPodSpec{
		InterfaceName: request.GetInterfaceName(),
		NetnsName:     request.GetNetns(),
	}
}

func (s *Server) Add(ctx context.Context, request *pb.AddRequest) (*pb.AddReply, error) {
	if request.GetDesiredHostInterfaceName() != "" {
		s.log.Warn("Desired host side interface name passed, this is not supported with VPP, ignoring it")
	}
	podSpec, err := NewLocalPodSpecFromAdd(request)
	if err != nil {
		s.log.Errorf("Error parsing interface add request %v %v", request, err)
		return &pb.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}

	s.log.Infof("Add request %s", podSpec.String())
	s.BarrierSync()
	s.lock.Lock()
	defer s.lock.Unlock()
	swIfIndex, err := s.AddVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
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
	s.log.Infof("Interface add successful: %s", podSpec.String())
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

func (s *Server) rescanState() error {
	numVPPWorkers, err := s.vpp.GetNumVPPWorkers()
	s.NumVPPWorkers = numVPPWorkers
	if err != nil {
		s.log.Panicf("Error getting number of VPP workers: %v", err)
	}

	podSpecs, err := storage.LoadCniServerState(config.CniServerStateFile)
	if err != nil {
		s.log.Errorf("Error getting pods %v", err)
		return err
	}
	for _, podSpec := range podSpecs {
		s.log.Infof("Rescanning pod %v", podSpec.String())
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

func (p *Server) OnVppRestart() {
	for name, podSpec := range p.podInterfaceMap {
		_, err := p.AddVppInterface(&podSpec, false /* doHostSideConf */)
		if err != nil {
			p.log.Errorf("Error re-injecting interface %s : %v", name, err)
		}
	}
}

func (s *Server) Del(ctx context.Context, request *pb.DelRequest) (*pb.DelReply, error) {
	podSpec := NewLocalPodSpecFromDel(request)

	s.log.Infof("Del request %s", podSpec.Key())
	s.BarrierSync()
	s.lock.Lock()
	defer s.lock.Unlock()
	err := s.DelVppInterface(podSpec)
	if err != nil {
		s.log.Warnf("Interface del failed %s : %v", podSpec.Key(), err)
		return &pb.DelReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}

	initialSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if !ok {
		s.log.Warnf("Deleting interface but initial spec not found")
	} else {
		s.policyServer.WorkloadRemoved(&policy.WorkloadEndpointID{
			OrchestratorID: initialSpec.OrchestratorID,
			WorkloadID:     initialSpec.WorkloadID,
			EndpointID:     initialSpec.EndpointID,
		})
	}

	delete(s.podInterfaceMap, podSpec.Key())
	s.log.Infof("Interface del successful %s", podSpec.Key())
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

	vppLinuxMtu, err := fetchVppLinuxMtu()
	if err != nil {
		l.Warn("failed to fetch vpp linux mtu")
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
		vppLinuxMtu:     vppLinuxMtu,
	}
	pb.RegisterCniDataplaneServer(server.grpcServer, server)
	l.Infof("Server starting")
	return server, nil
}

func (s *Server) Serve() {
	s.rescanState()
	err := s.grpcServer.Serve(s.socketListener)
	if err != nil {
		s.log.Fatalf("Failed to serve: %v", err)
	}
}
