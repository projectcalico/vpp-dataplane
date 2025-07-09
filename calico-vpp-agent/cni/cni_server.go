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
	gerrors "errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/pod_interface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
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

	RedirectToHostClassifyTableIndex uint32

	networkDefinitions   sync.Map
	cniMultinetEventChan chan common.CalicoVppEvent
	nodeBGPSpec          *common.LocalNodeSpec
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

func (s *Server) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func (s *Server) newLocalPodSpecFromAdd(request *cniproto.AddRequest) (*storage.LocalPodSpec, error) {
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
		if !*config.GetCalicoVppFeatureGates().MultinetEnabled {
			return nil, fmt.Errorf("enable multinet in config for multiple networks")
		}
		if isMemif(podSpec.InterfaceName) {
			if !*config.GetCalicoVppFeatureGates().MemifEnabled {
				return nil, fmt.Errorf("enable memif in config for memif interfaces")
			}
			podSpec.EnableMemif = true
			podSpec.DefaultIfType = storage.VppIfTypeMemif
			podSpec.IfSpec = GetDefaultIfSpec(false)
		}
	}

	for _, port := range request.Workload.Ports {
		hostIP := net.ParseIP(port.HostIp)
		var hostIP4, hostIP6 net.IP
		hostPort := uint16(port.HostPort)
		if hostPort != 0 && hostIP != nil && !hostIP.IsUnspecified() {
			if hostIP.To4() == nil {
				hostIP6 = hostIP
			} else {
				hostIP4 = hostIP
			}
			podSpec.HostPorts = append(podSpec.HostPorts, storage.HostPortBinding{
				HostPort:      hostPort,
				HostIP4:       hostIP4,
				HostIP6:       hostIP6,
				ContainerPort: uint16(port.Port),
				Protocol:      getHostEndpointProto(port.Protocol),
			})
		} else if hostPort != 0 {
			// default to node IP
			if s.nodeBGPSpec.IPv4Address != nil {
				hostIP4 = s.nodeBGPSpec.IPv4Address.IP
			}
			if s.nodeBGPSpec.IPv6Address != nil {
				hostIP6 = s.nodeBGPSpec.IPv6Address.IP
			}
			podSpec.HostPorts = append(podSpec.HostPorts, storage.HostPortBinding{
				HostPort:      hostPort,
				HostIP4:       hostIP4,
				HostIP6:       hostIP6,
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
	if podSpec.NetworkName != "" {
		value, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			s.log.Errorf("trying to create a pod in an unexisting network %s", podSpec.NetworkName)
		} else {
			networkDefinition, ok := value.(*watchers.NetworkDefinition)
			if !ok || networkDefinition == nil {
				panic("Value is not of type *watchers.NetworkDefinition")
			}
			_, route, err := net.ParseCIDR(networkDefinition.Range)
			if err == nil {
				podSpec.Routes = append(podSpec.Routes, storage.LocalIPNet{
					IP:   route.IP,
					Mask: route.Mask,
				})
			}
		}
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

func NewLocalPodSpecFromDel(request *cniproto.DelRequest) *storage.LocalPodSpec {
	return &storage.LocalPodSpec{
		InterfaceName: request.GetInterfaceName(),
		NetnsName:     request.GetNetns(),
	}
}

func (s *Server) Add(ctx context.Context, request *cniproto.AddRequest) (*cniproto.AddReply, error) {
	/* We don't support request.GetDesiredHostInterfaceName() */
	podSpec, err := s.newLocalPodSpecFromAdd(request)
	if err != nil {
		s.log.Errorf("Error parsing interface add request %v %v", request, err)
		return &cniproto.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	if podSpec.NetnsName == "" {
		s.log.Debugf("no netns passed, skipping")
		return &cniproto.AddReply{
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
		return &cniproto.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	if len(config.GetCalicoVppInitialConfig().RedirectToHostRules) != 0 && podSpec.NetworkName == "" {
		err := s.AddRedirectToHostToInterface(podSpec.TunTapSwIfIndex)
		if err != nil {
			return nil, err
		}
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
	return &cniproto.AddReply{
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

	if *config.GetCalicoVppFeatureGates().VCLEnabled {
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
		if len(config.GetCalicoVppInitialConfig().RedirectToHostRules) != 0 && podSpecCopy.NetworkName == "" {
			err := s.AddRedirectToHostToInterface(podSpecCopy.TunTapSwIfIndex)
			if err != nil {
				s.log.Error(err)
			}
		}
	}
}

func (s *Server) DelRedirectToHostOnInterface(swIfIndex uint32) error {
	err := s.vpp.SetClassifyInputInterfaceTables(swIfIndex, s.RedirectToHostClassifyTableIndex, types.InvalidTableId, types.InvalidTableId, false /*isAdd*/)
	if err != nil {
		return errors.Wrapf(err, "Error deleting classify input table from interface")
	} else {
		s.log.Infof("pod(del) delete input acl table %d from interface %d successfully", s.RedirectToHostClassifyTableIndex, swIfIndex)
		return nil
	}
}

func (s *Server) AddRedirectToHostToInterface(swIfIndex uint32) error {
	s.log.Infof("Setting classify input acl table %d on interface %d", s.RedirectToHostClassifyTableIndex, swIfIndex)
	err := s.vpp.SetClassifyInputInterfaceTables(swIfIndex, s.RedirectToHostClassifyTableIndex, types.InvalidTableId, types.InvalidTableId, true)
	if err != nil {
		s.log.Warnf("Error setting classify input table: %s, retrying...", err)
		return errors.Errorf("could not set input acl table %d for interface %d", s.RedirectToHostClassifyTableIndex, swIfIndex)
	} else {
		s.log.Infof("set input acl table %d for interface %d successfully", s.RedirectToHostClassifyTableIndex, swIfIndex)
		return nil
	}
}

func (s *Server) Del(ctx context.Context, request *cniproto.DelRequest) (*cniproto.DelReply, error) {
	partialPodSpec := NewLocalPodSpecFromDel(request)
	// Only try to delete the device if a namespace was passed in.
	if partialPodSpec.NetnsName == "" {
		s.log.Debugf("no netns passed, skipping")
		return &cniproto.DelReply{
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

	return &cniproto.DelReply{
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
forloop:
	for {
		select {
		case <-t.Dying():
			break forloop
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
				if old != nil && calicov3.VXLANMode(old.VxlanMode) != calicov3.VXLANModeNever && calicov3.VXLANMode(old.VxlanMode) != "" {
					vxlanEncapRefCountDelta--
				}
				if old != nil && calicov3.IPIPMode(old.IpipMode) != calicov3.IPIPModeNever && calicov3.IPIPMode(old.IpipMode) != "" {
					ipipEncapRefCountDelta--
				}
				if new != nil && calicov3.VXLANMode(new.VxlanMode) != calicov3.VXLANModeNever && calicov3.VXLANMode(new.VxlanMode) != "" {
					vxlanEncapRefCountDelta++
				}
				if new != nil && calicov3.IPIPMode(new.IpipMode) != calicov3.IPIPModeNever && calicov3.IPIPMode(new.IpipMode) != "" {
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
	return nil
}

func (s *Server) getMainInterface() *config.UplinkStatus {
	for _, i := range common.VppManagerInfo.UplinkStatuses {
		if i.IsMain {
			return &i
		}
	}
	return nil
}

func (s *Server) createRedirectToHostRules() (uint32, error) {
	var maxNumEntries uint32
	if len(config.GetCalicoVppInitialConfig().RedirectToHostRules) != 0 {
		maxNumEntries = uint32(2 * len(config.GetCalicoVppInitialConfig().RedirectToHostRules))
	} else {
		maxNumEntries = 1
	}
	index, err := s.vpp.AddClassifyTable(&types.ClassifyTable{
		Mask:           types.DstThreeTupleMask,
		NextTableIndex: types.InvalidID,
		MaxNumEntries:  maxNumEntries,
		MissNextIndex:  ^uint32(0),
	})
	if err != nil {
		return types.InvalidID, err
	}
	mainInterface := s.getMainInterface()
	if mainInterface == nil {
		return types.InvalidID, fmt.Errorf("No main interface found")
	}
	for _, rule := range config.GetCalicoVppInitialConfig().RedirectToHostRules {
		err = s.vpp.AddSessionRedirect(&types.SessionRedirect{
			FiveTuple:  types.NewDst3Tuple(rule.Proto, net.ParseIP(rule.Ip), rule.Port),
			TableIndex: index,
		}, &types.RoutePath{Gw: config.VppHostPuntFakeGatewayAddress, SwIfIndex: mainInterface.TapSwIfIndex})
		if err != nil {
			return types.InvalidID, err
		}
	}

	return index, nil
}

func (s *Server) ServeCNI(t *tomb.Tomb) error {
	err := syscall.Unlink(config.CNIServerSocket)
	if err != nil && !gerrors.Is(err, os.ErrNotExist) {
		s.log.Warnf("unable to unlink cni server socket: %+v", err)
	}

	socketListener, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on %s", config.CNIServerSocket)
	}

	s.RedirectToHostClassifyTableIndex, err = s.createRedirectToHostRules()
	if err != nil {
		return err
	}
	cniproto.RegisterCniDataplaneServer(s.grpcServer, s)

	if *config.GetCalicoVppFeatureGates().MultinetEnabled {
		netsSynced := make(chan bool)
		go func() {
			for {
				select {
				case <-t.Dying():
					s.log.Warn("Cni server asked to exit")
					return
				case event := <-s.cniMultinetEventChan:
					switch event.Type {
					case common.NetsSynced:
						netsSynced <- true
					case common.NetAddedOrUpdated:
						netDef, ok := event.New.(*watchers.NetworkDefinition)
						if !ok {
							s.log.Errorf("event.New is not a *watchers.NetworkDefinition %v", event.New)
							continue
						}
						s.networkDefinitions.Store(netDef.Name, netDef)
					case common.NetDeleted:
						netDef, ok := event.Old.(*watchers.NetworkDefinition)
						if !ok {
							s.log.Errorf("event.Old is not a *watchers.NetworkDefinition %v", event.Old)
							continue
						}
						s.networkDefinitions.Delete(netDef.Name)
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
	s.networkDefinitions.Store(networkDefinition.Name, networkDefinition)
}
