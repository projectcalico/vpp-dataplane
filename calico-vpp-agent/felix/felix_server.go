// Copyright (C) 2020 Cisco Systems Inc.
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

package felix

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/connectivity"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/policies"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/services"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type NodeWatcherRestartError struct{}

func (e NodeWatcherRestartError) Error() string {
	return "node configuration changed, restarting"
}

// Server holds all the data required to configure the policies defined by felix in VPP
type Server struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	felixServerEventChan chan any

	GotOurNodeBGPchan chan interface{}

	policiesHandler     *policies.PoliciesHandler
	cniHandler          *cni.CNIHandler
	connectivityHandler *connectivity.ConnectivityHandler
	serviceHandler      *services.ServiceHandler
}

// NewFelixServer creates a felix server
func NewFelixServer(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, log *logrus.Entry) *Server {
	cache := cache.NewCache(log)
	server := &Server{
		log: log,
		vpp: vpp,

		felixServerEventChan: make(chan any, common.ChanSize),

		GotOurNodeBGPchan: make(chan interface{}),

		cache:               cache,
		policiesHandler:     policies.NewPoliciesHandler(vpp, cache, clientv3, log),
		cniHandler:          cni.NewCNIHandler(vpp, cache, log),
		connectivityHandler: connectivity.NewConnectivityHandler(vpp, cache, clientv3, log),
		serviceHandler:      services.NewServiceHandler(vpp, cache, log),
	}

	reg := common.RegisterHandler(server.felixServerEventChan, "felix server events")
	reg.ExpectEvents(
		common.PodAdded,
		common.PodDeleted,
		common.TunnelAdded,
		common.TunnelDeleted,
		common.NetAddedOrUpdated,
		common.NetDeleted,
		common.ConnectivityAdded,
		common.ConnectivityDeleted,
		common.SRv6PolicyAdded,
		common.SRv6PolicyDeleted,
	)

	return server
}

func (s *Server) GetFelixServerEventChan() chan any {
	return s.felixServerEventChan
}

func (s *Server) GetCache() *cache.Cache {
	return s.cache
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.cache.BGPConf = bgpConf
}

// HandleBGPConfigurationChange is called when the BGPConfiguration changes.
// Handling of BGPConfiguration updates is not yet implemented, instead,
// we log and trigger a restart to ensure the system reloads configuration.
func (s *Server) HandleBGPConfigurationChange() error {
	s.log.Error("BGPConf updated")
	return errors.Errorf("BGPConf updated, restarting")
}

func (s *Server) getMainInterface() *config.UplinkStatus {
	for _, i := range common.VppManagerInfo.UplinkStatuses {
		if i.IsMain {
			return &i
		}
	}
	return nil
}

func (s *Server) createRedirectToHostRules() error {
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
		return err
	}
	mainInterface := s.getMainInterface()
	if mainInterface == nil {
		return fmt.Errorf("no main interface found")
	}
	for _, rule := range config.GetCalicoVppInitialConfig().RedirectToHostRules {
		err = s.vpp.AddSessionRedirect(&types.SessionRedirect{
			FiveTuple:  types.NewDst3Tuple(rule.Proto, net.ParseIP(rule.IP), rule.Port),
			TableIndex: index,
		}, &types.RoutePath{Gw: config.VppHostPuntFakeGatewayAddress, SwIfIndex: mainInterface.TapSwIfIndex})
		if err != nil {
			return err
		}
	}

	s.cache.RedirectToHostClassifyTableIndex = index
	return nil
}

func (s *Server) fetchNumDataThreads() error {
	nVppWorkers, err := s.vpp.GetNumVPPWorkers()
	if err != nil {
		return errors.Wrap(err, "Error getting number of VPP workers")
	}
	nDataThreads := nVppWorkers
	if config.GetCalicoVppIpsec().IpsecNbAsyncCryptoThread > 0 {
		nDataThreads = nVppWorkers - config.GetCalicoVppIpsec().IpsecNbAsyncCryptoThread
		if nDataThreads <= 0 {
			s.log.Errorf("Couldn't fulfill request [crypto=%d total=%d]", config.GetCalicoVppIpsec().IpsecNbAsyncCryptoThread, nVppWorkers)
			nDataThreads = nVppWorkers
		}
		s.log.Infof("Using ipsec workers [data=%d crypto=%d]", nDataThreads, nVppWorkers-nDataThreads)
	}
	s.cache.NumDataThreads = nDataThreads
	return nil
}

func (s *Server) fetchBufferConfig() error {
	availableBuffers, _, _, err := s.vpp.GetBufferStats()
	if err != nil {
		return errors.Wrap(err, "could not get available buffers")
	}
	s.cache.VppAvailableBuffers = uint64(availableBuffers)
	return nil
}

// Serve runs the felix server
// it does the bulk of the policy sync job. It starts by reconciling the current
// configured state in VPP (empty at first) with what is sent by felix, and once both are in
// sync, it keeps processing felix updates. It also sends endpoint updates to felix when the
// CNI component adds or deletes container interfaces.
func (s *Server) ServeFelix(t *tomb.Tomb) error {
	s.log.Info("Starting felix server")

	err := s.createRedirectToHostRules()
	if err != nil {
		return errors.Wrap(err, "Error in createRedirectToHostRules")
	}
	err = s.fetchNumDataThreads()
	if err != nil {
		return errors.Wrap(err, "Error in fetchNumDataThreads")
	}
	err = s.fetchBufferConfig()
	if err != nil {
		return errors.Wrap(err, "Error in fetchBufferConfig")
	}

	err = s.policiesHandler.PoliciesHandlerInit()
	if err != nil {
		return errors.Wrap(err, "Error in PoliciesHandlerInit")
	}
	err = s.cniHandler.CNIHandlerInit()
	if err != nil {
		return errors.Wrap(err, "Error in CNIHandlerInit")
	}
	for {
		select {
		case <-t.Dying():
			s.log.Warn("Felix server exiting")
			return nil
		case msg := <-s.felixServerEventChan:
			err = s.handleFelixServerEvents(msg)
			if err != nil {
				return errors.Wrapf(err, "Error handling FelixServerEvents")
			}
		}
	}
}

// felixLateInit takes care of setting up the handlers after
// their requirements have been received. This is needed
// as e.g. connecivity does not support support starting
// up without knowing node IPs
func (s *Server) felixLateInit() (err error) {
	err = s.connectivityHandler.ConnectivityHandlerInit()
	if err != nil {
		return errors.Wrap(err, "Error in ConnectivityHandlerInit")
	}
	err = s.serviceHandler.ServiceHandlerInit()
	if err != nil {
		return errors.Wrap(err, "Error in ServiceHandlerInit")
	}
	return nil
}

func (s *Server) handleFelixServerEvents(msg interface{}) (err error) {
	s.log.Debugf("Got message from felix: %#v", msg)
	switch evt := msg.(type) {
	case *common.ServiceEndpointsUpdate:
		s.serviceHandler.OnServiceEndpointsUpdate(evt)
	case *common.ServiceEndpointsDelete:
		s.serviceHandler.OnServiceEndpointsDelete(evt)
	case *proto.ConfigUpdate:
		err = s.handleConfigUpdate(evt)
	case *proto.InSync:
		err = s.policiesHandler.OnInSync(evt)
	case *common.FelixSocketStateChanged:
		s.policiesHandler.OnFelixSocketStateChanged(evt)
	case *proto.IPSetUpdate:
		err = s.policiesHandler.OnIpsetUpdate(evt)
	case *proto.IPSetDeltaUpdate:
		err = s.policiesHandler.OnIpsetDeltaUpdate(evt)
	case *proto.IPSetRemove:
		err = s.policiesHandler.OnIpsetRemove(evt)
	case *proto.ActivePolicyUpdate:
		err = s.policiesHandler.OnActivePolicyUpdate(evt)
	case *proto.ActivePolicyRemove:
		err = s.policiesHandler.OnActivePolicyRemove(evt)
	case *proto.ActiveProfileUpdate:
		err = s.policiesHandler.OnActiveProfileUpdate(evt)
	case *proto.ActiveProfileRemove:
		err = s.policiesHandler.OnActiveProfileRemove(evt)
	case *proto.HostEndpointUpdate:
		err = s.policiesHandler.OnHostEndpointUpdate(evt)
	case *proto.HostEndpointRemove:
		err = s.policiesHandler.OnHostEndpointRemove(evt)
	case *proto.WorkloadEndpointUpdate:
		err = s.policiesHandler.OnWorkloadEndpointUpdate(evt)
	case *proto.WorkloadEndpointRemove:
		err = s.policiesHandler.OnWorkloadEndpointRemove(evt)
	case *proto.HostMetadataUpdate:
		s.log.Debugf("Ignoring HostMetadataUpdate")
	case *proto.HostMetadataRemove:
		s.log.Debugf("Ignoring HostMetadataRemove")
	case *proto.HostMetadataV4V6Update:
		err = s.handleHostMetadataV4V6Update(evt)
	case *proto.HostMetadataV4V6Remove:
		err = s.handleHostMetadataV4V6Remove(evt)
	case *proto.IPAMPoolUpdate:
		err = s.handleIpamPoolUpdate(evt)
	case *proto.IPAMPoolRemove:
		err = s.handleIpamPoolRemove(evt)
	case *proto.ServiceAccountUpdate:
		s.log.Debugf("Ignoring ServiceAccountUpdate")
	case *proto.ServiceAccountRemove:
		s.log.Debugf("Ignoring ServiceAccountRemove")
	case *proto.NamespaceUpdate:
		s.log.Debugf("Ignoring NamespaceUpdate")
	case *proto.NamespaceRemove:
		s.log.Debugf("Ignoring NamespaceRemove")
	case *proto.GlobalBGPConfigUpdate:
		s.log.Infof("Got GlobalBGPConfigUpdate")
	case *proto.WireguardEndpointUpdate:
		err = s.connectivityHandler.OnWireguardEndpointUpdate(evt)
	case *proto.WireguardEndpointRemove:
		err = s.connectivityHandler.OnWireguardEndpointRemove(evt)
	case *model.CniPodAddEvent:
		err = s.cniHandler.OnPodAdd(evt)
	case *model.CniPodDelEvent:
		s.cniHandler.OnPodDelete(evt)
	case common.CalicoVppEvent:
		/* Note: we will only receive events we ask for when registering the chan */
		switch evt.Type {
		case common.NetAddedOrUpdated:
			new, ok := evt.New.(*common.NetworkDefinition)
			if !ok {
				return fmt.Errorf("evt.New is not a (*common.NetworkDefinition) %v", evt.New)
			}
			old, ok := evt.Old.(*common.NetworkDefinition)
			if !ok {
				return fmt.Errorf("evt.Old is not a (*common.NetworkDefinition) %v", evt.New)
			}
			s.cache.NetworkDefinitions[new.Name] = new
			s.cache.Networks[new.Vni] = new
			s.cniHandler.OnNetAddedOrUpdated(old, new)
		case common.NetDeleted:
			netDef, ok := evt.Old.(*common.NetworkDefinition)
			if !ok {
				return fmt.Errorf("evt.Old is not a (*common.NetworkDefinition) %v", evt.Old)
			}
			delete(s.cache.NetworkDefinitions, netDef.Name)
			delete(s.cache.Networks, netDef.Vni)
			s.cniHandler.OnNetDeleted(netDef)
		case common.PodAdded:
			podSpec, ok := evt.New.(*model.LocalPodSpec)
			if !ok {
				return fmt.Errorf("evt.New is not a (*model.LocalPodSpec) %v", evt.New)
			}
			swIfIndex := podSpec.TunTapSwIfIndex
			if swIfIndex == vpplink.InvalidID {
				swIfIndex = podSpec.MemifSwIfIndex
			}
			s.policiesHandler.OnWorkloadAdded(&policies.WorkloadEndpointID{
				OrchestratorID: podSpec.OrchestratorID,
				WorkloadID:     podSpec.WorkloadID,
				EndpointID:     podSpec.EndpointID,
				Network:        podSpec.NetworkName,
			}, swIfIndex, podSpec.InterfaceName, podSpec.GetContainerIPs())
		case common.PodDeleted:
			podSpec, ok := evt.Old.(*model.LocalPodSpec)
			if !ok {
				return fmt.Errorf("evt.Old is not a (*model.LocalPodSpec) %v", evt.Old)
			}
			if podSpec != nil {
				s.policiesHandler.OnWorkloadRemoved(&policies.WorkloadEndpointID{
					OrchestratorID: podSpec.OrchestratorID,
					WorkloadID:     podSpec.WorkloadID,
					EndpointID:     podSpec.EndpointID,
					Network:        podSpec.NetworkName,
				}, podSpec.GetContainerIPs())
			}
		case common.TunnelAdded:
			swIfIndex, ok := evt.New.(uint32)
			if !ok {
				return fmt.Errorf("evt.New not a uint32 %v", evt.New)
			}
			s.policiesHandler.OnTunnelAdded(swIfIndex)
		case common.TunnelDeleted:
			swIfIndex, ok := evt.Old.(uint32)
			if !ok {
				return fmt.Errorf("evt.Old not a uint32 %v", evt.Old)
			}
			s.policiesHandler.OnTunnelDelete(swIfIndex)
		case common.ConnectivityAdded:
			new, ok := evt.New.(*common.NodeConnectivity)
			if !ok {
				s.log.Errorf("evt.New is not a *common.NodeConnectivity %v", evt.New)
			}
			err := s.connectivityHandler.UpdateIPConnectivity(new, false /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while adding connectivity %s", err)
			}
		case common.ConnectivityDeleted:
			old, ok := evt.Old.(*common.NodeConnectivity)
			if !ok {
				s.log.Errorf("evt.Old is not a *common.NodeConnectivity %v", evt.Old)
			}
			err := s.connectivityHandler.UpdateIPConnectivity(old, true /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while deleting connectivity %s", err)
			}
		case common.SRv6PolicyAdded:
			new, ok := evt.New.(*common.NodeConnectivity)
			if !ok {
				s.log.Errorf("evt.New is not a *common.NodeConnectivity %v", evt.New)
			}
			err := s.connectivityHandler.UpdateSRv6Policy(new, false /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while adding SRv6 Policy %s", err)
			}
		case common.SRv6PolicyDeleted:
			old, ok := evt.Old.(*common.NodeConnectivity)
			if !ok {
				s.log.Errorf("evt.Old is not a *common.NodeConnectivity %v", evt.Old)
			}
			err := s.connectivityHandler.UpdateSRv6Policy(old, true /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while deleting SRv6 Policy %s", err)
			}
		default:
			s.log.Warnf("Unhandled CalicoVppEvent.Type: %s", evt.Type)
		}
	default:
		s.log.Warnf("Unhandled message from felix: %v", evt)
	}
	return err
}
