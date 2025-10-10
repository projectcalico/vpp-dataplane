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

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type Server struct {
	cniproto.UnimplementedCniDataplaneServer
	log *logrus.Entry
	vpp *vpplink.VppLink

	felixServerIpam common.FelixServerIpam

	grpcServer *grpc.Server

	podInterfaceMap map[string]model.LocalPodSpec
	lock            sync.Mutex /* protects Add/DelVppInterace/RescanState */
	cniEventChan    chan any

	memifDriver    *podinterface.MemifPodInterfaceDriver
	tuntapDriver   *podinterface.TunTapPodInterfaceDriver
	vclDriver      *podinterface.VclPodInterfaceDriver
	loopbackDriver *podinterface.LoopbackPodInterfaceDriver

	availableBuffers uint64

	RedirectToHostClassifyTableIndex uint32

	networkDefinitions   sync.Map
	cniMultinetEventChan chan any
	nodeBGPSpec          *common.LocalNodeSpec
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
}

func (s *Server) SetFelixConfig(felixConfig *felixConfig.Config) {
	s.tuntapDriver.SetFelixConfig(felixConfig)
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func (s *Server) Add(ctx context.Context, request *cniproto.AddRequest) (*cniproto.AddReply, error) {
	/* We don't support request.GetDesiredHostInterfaceName() */
	podSpec, err := model.NewLocalPodSpecFromAdd(request, s.nodeBGPSpec)
	if err != nil {
		s.log.Errorf("Error parsing interface add request %v %v", request, err)
		return &cniproto.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	if podSpec.NetworkName != "" {
		value, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			return nil, fmt.Errorf("trying to create a pod in an unexisting network %s", podSpec.NetworkName)
		} else {
			networkDefinition, ok := value.(*common.NetworkDefinition)
			if !ok || networkDefinition == nil {
				panic("Value is not of type *common.NetworkDefinition")
			}
			_, route, err := net.ParseCIDR(networkDefinition.Range)
			if err == nil {
				podSpec.Routes = append(podSpec.Routes, *route)
			}
		}
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
	err = model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		config.CniServerStateFilename,
	)
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

	cniServerState, err := model.LoadCniServerState(config.CniServerStateFilename)
	if err != nil {
		s.log.Errorf("Error getting pods from file %s, removing cache", err)
		err := os.Remove(config.CniServerStateFilename)
		if err != nil {
			s.log.Errorf("Could not remove %s, %s", config.CniServerStateFilename, err)
		}
	}

	s.log.Infof("RescanState: re-creating all interfaces")
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, podSpec := range cniServerState.PodSpecs {
		// we copy podSpec as a pointer to it will be sent over the event chan
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
	err := s.vpp.SetClassifyInputInterfaceTables(swIfIndex, s.RedirectToHostClassifyTableIndex, types.InvalidTableID, types.InvalidTableID, false /*isAdd*/)
	if err != nil {
		return errors.Wrapf(err, "Error deleting classify input table from interface")
	} else {
		s.log.Infof("pod(del) delete input acl table %d from interface %d successfully", s.RedirectToHostClassifyTableIndex, swIfIndex)
		return nil
	}
}

func (s *Server) AddRedirectToHostToInterface(swIfIndex uint32) error {
	s.log.Infof("Setting classify input acl table %d on interface %d", s.RedirectToHostClassifyTableIndex, swIfIndex)
	err := s.vpp.SetClassifyInputInterfaceTables(swIfIndex, s.RedirectToHostClassifyTableIndex, types.InvalidTableID, types.InvalidTableID, true)
	if err != nil {
		s.log.Warnf("Error setting classify input table: %s, retrying...", err)
		return errors.Errorf("could not set input acl table %d for interface %d", s.RedirectToHostClassifyTableIndex, swIfIndex)
	} else {
		s.log.Infof("set input acl table %d for interface %d successfully", s.RedirectToHostClassifyTableIndex, swIfIndex)
		return nil
	}
}

func (s *Server) Del(ctx context.Context, request *cniproto.DelRequest) (*cniproto.DelReply, error) {
	podSpecKey := model.LocalPodSpecKey(request.GetNetns(), request.GetInterfaceName())
	// Only try to delete the device if a namespace was passed in.
	if request.GetNetns() == "" {
		s.log.Debugf("no netns passed, skipping")
		return &cniproto.DelReply{
			Successful: true,
		}, nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("pod(del) key=%s", podSpecKey)
	initialSpec, ok := s.podInterfaceMap[podSpecKey]
	if !ok {
		s.log.Warnf("Unknown pod to delete key=%s", podSpecKey)
	} else {
		s.log.Infof("pod(del) spec=%s", initialSpec.String())
		s.DelVppInterface(&initialSpec)
		s.log.Infof("pod(del) Done! spec=%s", initialSpec.String())
	}

	delete(s.podInterfaceMap, podSpecKey)
	err := model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		config.CniServerStateFilename,
	)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}

	return &cniproto.DelReply{
		Successful: true,
	}, nil
}

// Serve runs the grpc server for the Calico CNI backend API
func NewCNIServer(vpp *vpplink.VppLink, felixServerIpam common.FelixServerIpam, log *logrus.Entry) *Server {
	server := &Server{
		vpp: vpp,
		log: log,

		felixServerIpam: felixServerIpam,
		cniEventChan:    make(chan any, common.ChanSize),

		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]model.LocalPodSpec),
		tuntapDriver:    podinterface.NewTunTapPodInterfaceDriver(vpp, log),
		memifDriver:     podinterface.NewMemifPodInterfaceDriver(vpp, log),
		vclDriver:       podinterface.NewVclPodInterfaceDriver(vpp, log),
		loopbackDriver:  podinterface.NewLoopbackPodInterfaceDriver(vpp, log),

		cniMultinetEventChan: make(chan any, common.ChanSize),
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
		case msg := <-s.cniEventChan:
			evt, ok := msg.(common.CalicoVppEvent)
			if !ok {
				continue
			}
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
					for _, containerIP := range podSpec.GetContainerIPs() {
						podSpec.NeedsSnat = podSpec.NeedsSnat || s.felixServerIpam.IPNetNeedsSNAT(containerIP)
					}
					if NeededSnat != podSpec.NeedsSnat {
						for _, swIfIndex := range []uint32{podSpec.LoopbackSwIfIndex, podSpec.TunTapSwIfIndex, podSpec.MemifSwIfIndex} {
							if swIfIndex != vpplink.InvalidID {
								s.log.Infof("Enable/Disable interface[%d] SNAT", swIfIndex)
								for _, ipFamily := range vpplink.IPFamilies {
									err := s.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIP6, podSpec.NeedsSnat)
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
		return types.InvalidID, fmt.Errorf("no main interface found")
	}
	for _, rule := range config.GetCalicoVppInitialConfig().RedirectToHostRules {
		err = s.vpp.AddSessionRedirect(&types.SessionRedirect{
			FiveTuple:  types.NewDst3Tuple(rule.Proto, net.ParseIP(rule.IP), rule.Port),
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
				case msg := <-s.cniMultinetEventChan:
					event, ok := msg.(common.CalicoVppEvent)
					if !ok {
						continue
					}
					switch event.Type {
					case common.NetsSynced:
						netsSynced <- true
					case common.NetAddedOrUpdated:
						netDef, ok := event.New.(*common.NetworkDefinition)
						if !ok {
							s.log.Errorf("event.New is not a *common.NetworkDefinition %v", event.New)
							continue
						}
						s.networkDefinitions.Store(netDef.Name, netDef)
					case common.NetDeleted:
						netDef, ok := event.Old.(*common.NetworkDefinition)
						if !ok {
							s.log.Errorf("event.Old is not a *common.NetworkDefinition %v", event.Old)
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
func (s *Server) ForceAddingNetworkDefinition(networkDefinition *common.NetworkDefinition) {
	s.networkDefinitions.Store(networkDefinition.Name, networkDefinition)
}
