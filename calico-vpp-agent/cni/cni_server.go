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
	"syscall"

	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore/store"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/services"
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
	servicesServer  *services.Server
	podInterfaceMap map[string]*LocalPodSpec
	infoStoreMgr    infostore.Manager
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
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
	swIfIndex, err := s.AddVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
		s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err)
		return &pb.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}

	s.podInterfaceMap[podSpec.Key()] = podSpec
	err = s.persistCniServerState()
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
	s.log.Infof("Interface add successful: %s", podSpec.String())
	// XXX: container MAC doesn't make sense anymore, we just pass back a constant one.
	// How does calico / k8s use it?
	// Check if info Store manager interface is initialized and update pod information store
	if s.infoStoreMgr != nil {
		r := &infostore.Record{
			Name:          request.Workload.Name,
			Namespace:     request.Workload.Namespace,
			InterfaceName: podSpec.InterfaceName,
			IPs:           make([]net.IP, len(podSpec.ContainerIps)),
			// If ever Calico VPP starts using a non default table id, TableID will carry its value
			TableID: 0,
		}
		// Allocate and copy Pod's IPs into the information record
		for i := 0; i < len(podSpec.ContainerIps); i++ {
			r.IPs[i] = make([]byte, len(podSpec.ContainerIps[i].IP))
			copy(r.IPs[i], podSpec.ContainerIps[i].IP)
		}
		if err := s.infoStoreMgr.AddPodInfo(r); err != nil {
			s.log.Errorf("AddPodInfo errored %v", err)
		}
	}
	return &pb.AddReply{
		Successful:        true,
		HostInterfaceName: swIfIdxToIfName(swIfIndex),
		ContainerMac:      "02:00:00:00:00:00",
	}, nil
}

func (p *Server) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	return p.routingServer.IPNetNeedsSNAT(prefix)
}

func (s *Server) RescanState() error {
	podSpecs, err := s.loadCniServerState()
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
			s.podInterfaceMap[podSpec.Key()] = &podSpec
		}
	}
	return err
}

func (p *Server) OnVppRestart() {
	for name, podSpec := range p.podInterfaceMap {
		_, err := p.AddVppInterface(podSpec, false /* doHostSideConf */)
		if err != nil {
			p.log.Errorf("Error re-injecting interface %s : %v", name, err)
		}
	}
}

func (s *Server) Del(ctx context.Context, request *pb.DelRequest) (*pb.DelReply, error) {
	podSpec := NewLocalPodSpecFromDel(request)

	s.log.Infof("Del request %s", podSpec.Key())
	s.BarrierSync()
	err := s.DelVppInterface(podSpec)
	if err != nil {
		s.log.Warnf("Interface del failed %s : %v", podSpec.Key(), err)
		return &pb.DelReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	// Check if info Store manager interface is initialized and update pod information store
	if s.infoStoreMgr != nil {
		if err := s.infoStoreMgr.RemovePodInfo(podSpec.InterfaceName); err != nil {
			s.log.Errorf("RemovePodInfo errored %v", err)
		}
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
func NewServer(v *vpplink.VppLink, rs *routing.Server, ss *services.Server, l *logrus.Entry) (*Server, error) {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		panic(err.Error())
	}
	lis, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		l.Fatalf("failed to listen on %s: %v", config.CNIServerSocket, err)
		return nil, err
	}
	server := &Server{
		vpp:             v,
		log:             l,
		routingServer:   rs,
		servicesServer:  ss,
		socketListener:  lis,
		client:          client,
		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]*LocalPodSpec),
		infoStoreMgr:    store.NewInfoStore(),
	}
	pb.RegisterCniDataplaneServer(server.grpcServer, server)
	l.Infof("Server starting")
	return server, nil
}

func (s *Server) Serve() {
	err := s.grpcServer.Serve(s.socketListener)
	if err != nil {
		s.log.Fatalf("Failed to serve: %v", err)
	}
}
