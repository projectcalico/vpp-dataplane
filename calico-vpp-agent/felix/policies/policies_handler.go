// Copyright (C) 2025 Cisco Systems Inc.
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

package policies

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/pkg/errors"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// Server holds all the data required to configure the policies defined by felix in VPP
type PoliciesHandler struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	endpointsInterfaces map[WorkloadEndpointID]map[string]uint32
	tunnelSwIfIndexes   map[uint32]bool
	interfacesMap       map[string]interfaceDetails

	configuredState *PolicyState
	pendingState    *PolicyState

	state common.FelixSocketSyncState

	/* failSafe policies allow traffic on some ports irrespective of the policy */
	failSafePolicy *Policy
	/* workloadToHost may drop traffic that goes from the pods to the host */
	workloadsToHostPolicy  *Policy
	defaultTap0IngressConf []uint32
	defaultTap0EgressConf  []uint32
	/* always allow traffic coming from host to the pods (for healthchecks and so on) */
	// AllowFromHostPolicy persists the policy allowing host --> pod communications.
	// See CreateAllowFromHostPolicy definition
	AllowFromHostPolicy *Policy
	// allPodsIpset persists the ipset containing all the workload endpoints (pods) addresses
	allPodsIpset *IPSet
	/* allow traffic between uplink/tunnels and tap interfaces */
	allowToHostPolicy *Policy

	GotOurNodeBGPchan     chan *common.LocalNodeSpec
	GotOurNodeBGPchanOnce sync.Once
}

func NewPoliciesHandler(vpp *vpplink.VppLink, cache *cache.Cache, clientv3 calicov3cli.Interface, log *logrus.Entry) *PoliciesHandler {
	return &PoliciesHandler{
		log:                 log,
		vpp:                 vpp,
		cache:               cache,
		endpointsInterfaces: make(map[WorkloadEndpointID]map[string]uint32),
		tunnelSwIfIndexes:   make(map[uint32]bool),

		configuredState: NewPolicyState(),
		pendingState:    NewPolicyState(),
		state:           common.StateDisconnected,

		GotOurNodeBGPchan: make(chan *common.LocalNodeSpec),
	}
}

func (s *PoliciesHandler) GetState() *PolicyState {
	if s.state.IsPending() {
		return s.pendingState
	}
	return s.configuredState
}

func (s *PoliciesHandler) OnInSync(msg *proto.InSync) (err error) {
	if s.state != common.StateSyncing {
		return fmt.Errorf("received InSync but state was not syncing")
	}

	s.state = common.StateInSync
	s.log.Infof("Policies now in sync")
	return s.applyPendingState()
}

// workloadAdded is called by the CNI server when a container interface is created,
// either during startup when reconnecting the interfaces, or when a new pod is created
func (s *PoliciesHandler) OnWorkloadAdded(id *WorkloadEndpointID, swIfIndex uint32, ifName string, containerIPs []*net.IPNet) {
	// TODO: Send WorkloadEndpointStatusUpdate to felix

	intf, existing := s.endpointsInterfaces[*id]

	if existing {
		for _, exInt := range intf {
			if swIfIndex == exInt {
				return
			}
		}
		// VPP restarted and interfaces are being reconnected
		s.log.Warnf("workload endpoint changed interfaces, did VPP restart? %v %v -> %d", id, intf, swIfIndex)
		s.endpointsInterfaces[*id][ifName] = swIfIndex
	}

	s.log.Infof("policy(add) Workload id=%v swIfIndex=%d", id, swIfIndex)
	if s.endpointsInterfaces[*id] == nil {
		s.endpointsInterfaces[*id] = map[string]uint32{ifName: swIfIndex}
	} else {
		s.endpointsInterfaces[*id][ifName] = swIfIndex
	}

	if s.state == common.StateInSync {
		wep, ok := s.configuredState.WorkloadEndpoints[*id]
		if !ok {
			s.log.Infof("not creating wep in workloadadded")
			// Nothing to configure
		} else {
			s.log.Infof("creating wep in workloadadded")
			err := s.CreateWorkloadEndpoint(wep, []uint32{swIfIndex}, s.configuredState, id.Network)
			if err != nil {
				s.log.Errorf("Error processing workload addition: %s", err)
			}
		}
	}
	// EndpointToHostAction
	allMembers := []string{}
	for _, containerIP := range containerIPs {
		allMembers = append(allMembers, containerIP.IP.String())
	}
	err := s.allPodsIpset.AddMembers(allMembers, true, s.vpp)
	if err != nil {
		s.log.Errorf("Error processing workload addition: %s", err)
	}
}

// WorkloadRemoved is called by the CNI server when the interface of a pod is deleted
func (s *PoliciesHandler) OnWorkloadRemoved(id *WorkloadEndpointID, containerIPs []*net.IPNet) {
	// TODO: Send WorkloadEndpointStatusRemove to felix

	_, existing := s.endpointsInterfaces[*id]
	if !existing {
		s.log.Warnf("nonexistent workload endpoint removed %v", id)
		return
	}
	s.log.Infof("policy(del) workload id=%v", id)

	if s.state == common.StateInSync {
		wep, ok := s.configuredState.WorkloadEndpoints[*id]
		if !ok {
			// Nothing to clean up
		} else {
			err := s.DeleteWorkloadEndpoint(wep)
			if err != nil {
				s.log.Errorf("Error processing workload removal: %s", err)
			}
		}
	}
	delete(s.endpointsInterfaces, *id)
	// EndpointToHostAction
	allMembers := []string{}
	for _, containerIP := range containerIPs {
		allMembers = append(allMembers, containerIP.IP.String())
	}
	err := s.allPodsIpset.RemoveMembers(allMembers, true, s.vpp)
	if err != nil {
		s.log.Errorf("Error processing workload remove: %s", err)
	}
}

func (s *PoliciesHandler) OnTunnelAdded(swIfIndex uint32) {
	s.tunnelSwIfIndexes[swIfIndex] = true
	for _, h := range s.GetState().HostEndpoints {
		newTunnel := true
		for _, v := range h.TunnelSwIfIndexes {
			if v == swIfIndex {
				newTunnel = false
			}
		}
		if newTunnel {
			h.TunnelSwIfIndexes = append(h.TunnelSwIfIndexes, swIfIndex)
			s.log.Infof("Configuring policies on added tunnel [%d]", swIfIndex)
			if !s.state.IsPending() {
				s.log.Infof("policy(upd) interface swif=%d", swIfIndex)
				err := s.vpp.ConfigurePolicies(swIfIndex, h.CurrentForwardConf, 1 /*invertRxTx*/)
				if err != nil {
					s.log.WithError(err).Errorf("OnTunnelAdded: cannot configure policies on tunnel interface %d", swIfIndex)
				}
			}
		}
	}
}
func (s *PoliciesHandler) OnTunnelDelete(swIfIndex uint32) {
	delete(s.tunnelSwIfIndexes, swIfIndex)
	state := s.GetState()
	for _, h := range state.HostEndpoints {
		for index, existingSwifindex := range h.TunnelSwIfIndexes {
			if existingSwifindex == swIfIndex {
				// we don't delete the policies because they are auto-deleted when interfaces are removed
				h.TunnelSwIfIndexes = append(h.TunnelSwIfIndexes[:index], h.TunnelSwIfIndexes[index+1:]...)
			}
		}
	}
}

func (s *PoliciesHandler) OnFelixSocketStateChanged(evt *common.FelixSocketStateChanged) {
	s.state = evt.NewState
}

func (s *PoliciesHandler) OnFelixConfChanged(old, new *felixConfig.Config) {
	if s.state != common.StateConnected {
		s.log.Errorf("received ConfigUpdate but server is not in Connected state! state: %v", s.state)
		return
	}
	s.state = common.StateSyncing
	if s.cache.FelixConfig.DefaultEndpointToHostAction != old.DefaultEndpointToHostAction {
		s.log.Infof("Change in EndpointToHostAction to %+v", s.getEndpointToHostAction())
		workloadsToHostAllowRule := &Rule{
			VppID: types.InvalidID,
			Rule: &types.Rule{
				Action: s.getEndpointToHostAction(),
			},
			SrcIPSetNames: []string{"calico-vpp-wep-addr-ipset"},
		}
		policy := s.workloadsToHostPolicy.DeepCopy()
		policy.InboundRules = []*Rule{workloadsToHostAllowRule}
		err := s.workloadsToHostPolicy.Update(s.vpp, policy,
			&PolicyState{
				IPSets: map[string]*IPSet{
					"calico-vpp-wep-addr-ipset": s.allPodsIpset,
				},
			})
		if err != nil {
			s.log.Errorf("error updating workloadsToHostPolicy %v", err)
			return
		}
	}
	if !protoPortListEqual(s.cache.FelixConfig.FailsafeInboundHostPorts, old.FailsafeInboundHostPorts) ||
		!protoPortListEqual(s.cache.FelixConfig.FailsafeOutboundHostPorts, old.FailsafeOutboundHostPorts) {
		err := s.createFailSafePolicies()
		if err != nil {
			s.log.Errorf("error updating FailSafePolicies %v", err)
			return
		}
	}
}

// Reconciles the pending state with the configured state
func (s *PoliciesHandler) applyPendingState() (err error) {
	s.log.Infof("Reconciliating pending policy state with configured state")
	// Stupid algorithm for now, delete all that is in configured state, and then recreate everything
	for _, wep := range s.configuredState.WorkloadEndpoints {
		if len(wep.SwIfIndex) != 0 {
			err = s.DeleteWorkloadEndpoint(wep)
			if err != nil {
				return errors.Wrap(err, "cannot cleanup workload endpoint")
			}
		}
	}
	for _, policy := range s.configuredState.Policies {
		err = policy.Delete(s.vpp, s.configuredState)
		if err != nil {
			s.log.Warnf("error deleting policy: %v", err)
		}
	}
	for _, profile := range s.configuredState.Profiles {
		err = profile.Delete(s.vpp, s.configuredState)
		if err != nil {
			s.log.Warnf("error deleting profile: %v", err)
		}
	}
	for _, ipset := range s.configuredState.IPSets {
		err = ipset.Delete(s.vpp)
		if err != nil {
			s.log.Warnf("error deleting ipset: %v", err)
		}
	}
	for _, hep := range s.configuredState.HostEndpoints {
		if len(hep.UplinkSwIfIndexes) != 0 {
			err = s.DeleteHostEndpoint(hep, s.configuredState)
			if err != nil {
				s.log.Warnf("error deleting hostendpoint : %v", err)
			}
		}
	}

	s.configuredState = s.pendingState
	s.pendingState = NewPolicyState()
	for _, ipset := range s.configuredState.IPSets {
		err = ipset.Create(s.vpp)
		if err != nil {
			return errors.Wrap(err, "error creating ipset")
		}
	}
	for _, profile := range s.configuredState.Profiles {
		err = profile.Create(s.vpp, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "error creating profile")
		}
	}
	for _, policy := range s.configuredState.Policies {
		err = policy.Create(s.vpp, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "error creating policy")
		}
	}
	for id, wep := range s.configuredState.WorkloadEndpoints {
		intf, intfFound := s.endpointsInterfaces[id]
		if intfFound {
			swIfIndexList := []uint32{}
			for _, idx := range intf {
				swIfIndexList = append(swIfIndexList, idx)
			}
			err = s.CreateWorkloadEndpoint(wep, swIfIndexList, s.configuredState, id.Network)
			if err != nil {
				return errors.Wrap(err, "cannot configure workload endpoint")
			}
		}
	}
	for _, hep := range s.configuredState.HostEndpoints {
		err = s.CreateHostEndpoint(hep, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "cannot create host endpoint")
		}
	}
	s.log.Infof("Reconciliation done")
	return nil
}

func (s *PoliciesHandler) OnNodeAddUpdate(node *common.LocalNodeSpec) {
	if node.Name == *config.NodeName {
		err := s.createAllowFromHostPolicy()
		if err != nil {
			s.log.Errorf("Error in creating AllowFromHostPolicy %v", err)
			return
		}
		err = s.createAllowToHostPolicy()
		if err != nil {
			s.log.Errorf("Error in createAllowToHostPolicy %v", err)
			return
		}
	}
}

func (s *PoliciesHandler) getEndpointToHostAction() types.RuleAction {
	if strings.ToUpper(s.cache.FelixConfig.DefaultEndpointToHostAction) == "ACCEPT" {
		return types.ActionAllow
	}
	return types.ActionDeny
}
