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
	"strconv"
	"strings"
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
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	lock         sync.Mutex
	memifDriver  *pod_interface.MemifPodInterfaceDriver
	tuntapDriver *pod_interface.TunTapPodInterfaceDriver
	vclDriver    *pod_interface.VclPodInterfaceDriver
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
		DefaultIfType: storage.VppTun,

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
	workload := request.GetWorkload()
	if workload != nil {
		for k, v := range workload.Annotations {
			if k == "vcl" && v == "enable" {
				podSpec.IfPortConfigs = append(podSpec.IfPortConfigs, storage.LocalIfPortConfigs{
					IfType: storage.VppVcl,
				})
				continue
			}
			var ifType storage.VppInterfaceType
			switch v {
			case "memif":
				ifType = storage.VppMemif
			case "tun":
				ifType = storage.VppTun
			default:
				continue
			}
			if k == "all" {
				podSpec.DefaultIfType = ifType
				continue
			}
			parts := strings.Split(k, "-") /* tcp-1234 */
			if len(parts) != 2 && len(parts) != 3 {
				s.log.Warnf("Error parsing %s", k)
				continue
			}
			proto, err := types.UnformatProto(parts[0])
			if err != nil {
				s.log.Warnf("Error parsing %s %s", k, err)
				continue
			}
			start, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				s.log.Warnf("Error parsing port %s %s", k, err)
				continue
			}
			end := start
			if len(parts) == 3 {
				end, err = strconv.ParseInt(parts[2], 10, 32)
				if err != nil {
					s.log.Warnf("Error parsing port %s %s", k, err)
					continue
				}
			}
			podSpec.IfPortConfigs = append(podSpec.IfPortConfigs, storage.LocalIfPortConfigs{
				Start:  uint16(start),
				End:    uint16(end),
				Proto:  proto,
				IfType: ifType,
			})
		}
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
	// Only try to delete the device if a namespace was passed in.
	if podSpec.NetnsName == "" {
		s.log.Debugf("no netns passed, skipping")
		return &pb.DelReply{
			Successful: true,
		}, nil
	}
	s.log.Infof("Del request %s", podSpec.Key())
	s.BarrierSync()
	s.lock.Lock()
	defer s.lock.Unlock()

	initialSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if !ok {
		s.log.Warnf("Deleting interface but initial spec not found")
		s.DelVppInterface(podSpec)
	} else {
		s.policyServer.WorkloadRemoved(&policy.WorkloadEndpointID{
			OrchestratorID: initialSpec.OrchestratorID,
			WorkloadID:     initialSpec.WorkloadID,
			EndpointID:     initialSpec.EndpointID,
		})
		s.DelVppInterface(&initialSpec)
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
