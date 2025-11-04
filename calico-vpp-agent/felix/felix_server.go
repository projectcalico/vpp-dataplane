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
	"sync"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/policies"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// Server holds all the data required to configure the policies defined by felix in VPP
type Server struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	felixServerEventChan chan any

	felixConfigReceived bool
	FelixConfigChan     chan *felixConfig.Config

	ippoolLock      sync.RWMutex
	policiesHandler *policies.PoliciesHandler
}

// NewFelixServer creates a felix server
func NewFelixServer(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, log *logrus.Entry) *Server {
	cache := cache.NewCache(log)
	server := &Server{
		log: log,
		vpp: vpp,

		felixServerEventChan: make(chan any, common.ChanSize),

		felixConfigReceived: false,
		FelixConfigChan:     make(chan *felixConfig.Config),

		cache:           cache,
		policiesHandler: policies.NewPoliciesHandler(vpp, cache, clientv3, log),
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

func (s *Server) GotOurNodeBGPchan() chan *common.LocalNodeSpec {
	return s.policiesHandler.GotOurNodeBGPchan
}

func (s *Server) GetCache() *cache.Cache {
	return s.cache
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.cache.BGPConf = bgpConf
}

func (s *Server) GetPrefixIPPool(prefix *net.IPNet) *proto.IPAMPool {
	s.ippoolLock.RLock()
	defer s.ippoolLock.RUnlock()
	return s.cache.GetPrefixIPPool(prefix)
}

func (s *Server) IPNetNeedsSNAT(prefix *net.IPNet) bool {
	pool := s.GetPrefixIPPool(prefix)
	if pool == nil {
		return false
	} else {
		return pool.Masquerade
	}
}

// Serve runs the felix server
// it does the bulk of the policy sync job. It starts by reconciling the current
// configured state in VPP (empty at first) with what is sent by felix, and once both are in
// sync, it keeps processing felix updates. It also sends endpoint updates to felix when the
// CNI component adds or deletes container interfaces.
func (s *Server) ServeFelix(t *tomb.Tomb) error {
	s.log.Info("Starting felix server")

	err := s.policiesHandler.PoliciesHandlerInit()
	if err != nil {
		return errors.Wrap(err, "Error in PoliciesHandlerInit")
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

func (s *Server) handleFelixServerEvents(msg interface{}) (err error) {
	s.log.Debugf("Got message from felix: %#v", msg)
	switch evt := msg.(type) {
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
		err = s.policiesHandler.OnHostMetadataV4V6Update(evt)
	case *proto.HostMetadataV4V6Remove:
		err = s.policiesHandler.OnHostMetadataV4V6Remove(evt)
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
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPConfChanged,
		})
	case common.CalicoVppEvent:
		/* Note: we will only receive events we ask for when registering the chan */
		switch evt.Type {
		case common.NetAddedOrUpdated:
			new, ok := evt.New.(*common.NetworkDefinition)
			if !ok {
				return fmt.Errorf("evt.New is not a (*common.NetworkDefinition) %v", evt.New)
			}
			s.cache.NetworkDefinitions[new.Name] = new
			s.cache.Networks[new.Vni] = new
		case common.NetDeleted:
			netDef, ok := evt.Old.(*common.NetworkDefinition)
			if !ok {
				return fmt.Errorf("evt.Old is not a (*common.NetworkDefinition) %v", evt.Old)
			}
			delete(s.cache.NetworkDefinitions, netDef.Name)
			delete(s.cache.Networks, netDef.Vni)
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
		default:
			s.log.Warnf("Unhandled CalicoVppEvent.Type: %s", evt.Type)
		}
	default:
		s.log.Warnf("Unhandled message from felix: %v", evt)
	}
	return err
}
