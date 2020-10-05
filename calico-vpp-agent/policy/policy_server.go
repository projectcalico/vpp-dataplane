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

package policy

import (
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

type SyncState int

const (
	StateDisconnected SyncState = iota
	StateConnected
	StateSyncing
	StateInSync
)

// Server holds all the data required to configure the policies defined by felix in VPP
type Server struct {
	*common.CalicoVppServerData
	log            *logrus.Entry
	vpp            *vpplink.VppLink
	vppRestarted   chan bool
	felixRestarted chan bool
	exiting        chan bool

	state         SyncState
	nextSeqNumber uint64

	configuredState *PolicyState
	pendingState    *PolicyState
}

// NewServer creates a policy server
func NewServer(vpp *vpplink.VppLink, log *logrus.Entry) (*Server, error) {
	server := Server{
		log:            log,
		vpp:            vpp,
		vppRestarted:   make(chan bool),
		felixRestarted: make(chan bool),
		exiting:        make(chan bool),

		state:         StateDisconnected,
		nextSeqNumber: 0,

		configuredState: NewPolicyState(),
	}

	// Cleanup potentially left over socket
	err := os.RemoveAll(config.FelixDataplaneSocket)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not delete socket %s", config.FelixDataplaneSocket)
	}

	return &server, nil
}

// OnVppRestart notifies the policy server that vpp restarted
func (s *Server) OnVppRestart() {
	s.vppRestarted <- true
}

// Serve runs the policy server
func (s *Server) Serve() {
	s.log.Info("Starting policy server")
	listener, err := net.Listen("unix", config.FelixDataplaneSocket)
	if err != nil {
		s.log.WithError(err).Errorf("Could not bind to unix://%s", config.FelixDataplaneSocket)
		return
	}
	defer func() {
		listener.Close()
		os.RemoveAll(config.FelixDataplaneSocket)
	}()

	for {
		s.state = StateDisconnected
		// Accept only one connection
		conn, err := listener.Accept()
		if err != nil {
			s.log.WithError(err).Error("cannot accept policy client connection")
			return
		}
		s.state = StateConnected
		s.pendingState = NewPolicyState()

		go s.SyncPolicy(conn)

		select {
		case <-s.vppRestarted:
			// Close connection to restart felix, wipe all data and start over
			s.configuredState = NewPolicyState()
			err = conn.Close()
			if err != nil {
				s.log.WithError(err).Warn("Error closing unix connection to felix API proxy")
			}
		case <-s.felixRestarted:
			// Connection was closed. Just accept new one, state will be reconciled on startup.
		case <-s.exiting:
			err = conn.Close()
			if err != nil {
				s.log.WithError(err).Warn("Error closing unix connection to felix API proxy")
			}
			return
		}
	}
}

func (s *Server) RescanState() error {
	return nil
}

// Stop tells the policy server to exit
func (s *Server) Stop() {
	s.exiting <- true
}

// SyncPolicy does the bulk of the policy sync job. It starts by reconciling the current
// configured state in VPP (empty at first) with what is sent by felix, and once both are in
// sync, it keeps processing felix updates. It also sends endpoint updates to felix when the
// CNI component adds or deletes container interfaces.
func (s *Server) SyncPolicy(conn net.Conn) {
	s.log.Info("Starting policy resync")

	for {
		msg, err := s.RecvMessage(conn)
		if err != nil {
			s.log.WithError(err).Errorf("error communicating with felix")
			conn.Close()
			s.felixRestarted <- true
			return
		}
		s.log.Debugf("Got message from felix: %v", msg)
		switch m := msg.(type) {
		case *proto.ConfigUpdate:
			err = s.handleConfigUpdate(m)
		case *proto.InSync:
			err = s.handleInSync(m)
		default:
			var pending bool
			if s.state == StateSyncing {
				pending = true
			} else if s.state == StateInSync {
				pending = false
			} else {
				s.log.Errorf("Got message %#v but not in syncing or synced state", m)
				conn.Close()
				s.felixRestarted <- true
				return
			}
			switch m := msg.(type) {
			case *proto.IPSetUpdate:
				err = s.handleIpsetUpdate(m, pending)
			case *proto.IPSetDeltaUpdate:
				err = s.handleIpsetDeltaUpdate(m, pending)
			case *proto.IPSetRemove:
				err = s.handleIpsetRemove(m, pending)
			case *proto.ActivePolicyUpdate:
				err = s.handleActivePolicyUpdate(m, pending)
			case *proto.ActivePolicyRemove:
				err = s.handleActivePolicyRemove(m, pending)
			case *proto.ActiveProfileUpdate:
				err = s.handleActiveProfileUpdate(m, pending)
			case *proto.ActiveProfileRemove:
				err = s.handleActiveProfileRemove(m, pending)
			case *proto.HostEndpointUpdate:
				err = s.handleHostEndpointUpdate(m, pending)
			case *proto.HostEndpointRemove:
				err = s.handleHostEndpointRemove(m, pending)
			case *proto.WorkloadEndpointUpdate:
				err = s.handleWorkloadEndpointUpdate(m, pending)
			case *proto.WorkloadEndpointRemove:
				err = s.handleWorkloadEndpointRemove(m, pending)
			case *proto.HostMetadataUpdate:
				err = s.handleHostMetadataUpdate(m, pending)
			case *proto.HostMetadataRemove:
				err = s.handleHostMetadataRemove(m, pending)
			case *proto.IPAMPoolUpdate:
				err = s.handleIpamPoolUpdate(m, pending)
			case *proto.IPAMPoolRemove:
				err = s.handleIpamPoolRemove(m, pending)
			case *proto.ServiceAccountUpdate:
				err = s.handleServiceAccountUpdate(m, pending)
			case *proto.ServiceAccountRemove:
				err = s.handleServiceAccountRemove(m, pending)
			case *proto.NamespaceUpdate:
				err = s.handleNamespaceUpdate(m, pending)
			case *proto.NamespaceRemove:
				err = s.handleNamespaceRemove(m, pending)
			default:
				s.log.Warnf("Unhandled message from felix: %v", m)
			}
		}
		if err != nil {
			s.log.WithError(err).Error("Error processing update from felix, restarting")
			conn.Close()
			s.felixRestarted <- true
			return
		}
	}
}

func (s *Server) currentState(pending bool) *PolicyState {
	if pending {
		return s.pendingState
	}
	return s.configuredState
}

func (s *Server) handleConfigUpdate(msg *proto.ConfigUpdate) (err error) {
	if s.state != StateConnected {
		return fmt.Errorf("Received ConfigUpdate but server is not in Connected state! state: %v", s.state)
	}
	s.log.Infof("Got config from felix: %+v", msg)
	s.state = StateSyncing
	return nil
}

func (s *Server) handleInSync(msg *proto.InSync) (err error) {
	if s.state != StateSyncing {
		return fmt.Errorf("Received InSync but state was not syncing")
	}
	s.state = StateInSync
	s.log.Infof("Policies now in sync")
	return s.applyPendingState()
}

func (s *Server) handleIpsetUpdate(msg *proto.IPSetUpdate, pending bool) (err error) {
	ips, err := fromIPSetUpdate(msg)
	if err != nil {
		return errors.Wrap(err, "cannot process IPSetUpdate")
	}
	state := s.currentState(pending)
	_, ok := state.IPSets[msg.GetId()]
	if ok {
		return fmt.Errorf("Received new ipset for ID %s that already exists", msg.GetId())
	}
	if !pending {
		err = ips.Create(s.vpp)
		if err != nil {
			return errors.Wrapf(err, "cannot create ipset %s", msg.GetId())
		}
	}
	state.IPSets[msg.GetId()] = ips
	return nil
}

func (s *Server) handleIpsetDeltaUpdate(msg *proto.IPSetDeltaUpdate, pending bool) (err error) {
	ips, ok := s.currentState(pending).IPSets[msg.GetId()]
	if !ok {
		return fmt.Errorf("received delta update for non-existent ipset")
	}
	err = ips.AddMembers(msg.GetAddedMembers(), !pending, s.vpp)
	if err != nil {
		return errors.Wrap(err, "cannot process ipset delta update")
	}
	err = ips.RemoveMembers(msg.GetRemovedMembers(), !pending, s.vpp)
	if err != nil {
		return errors.Wrap(err, "cannot process ipset delta update")
	}
	return nil
}

func (s *Server) handleIpsetRemove(msg *proto.IPSetRemove, pending bool) (err error) {
	state := s.currentState(pending)
	_, ok := state.IPSets[msg.GetId()]
	if !ok {
		s.log.Debugf("Received ipset delete for ID %s that doesn't exists", msg.GetId())
		return nil
	}
	if !pending {
		err = state.IPSets[msg.GetId()].Delete(s.vpp)
		if err != nil {
			return errors.Wrapf(err, "cannot delete ipset %s", msg.GetId())
		}
	}
	delete(state.IPSets, msg.GetId())
	return nil
}

func (s *Server) handleActivePolicyUpdate(msg *proto.ActivePolicyUpdate, pending bool) (err error) {
	state := s.currentState(pending)
	id := PolicyID{
		Tier: msg.Id.Tier,
		Name: msg.Id.Name,
	}
	p, err := fromProtoPolicy(msg.Policy)
	if err != nil {
		return errors.Wrapf(err, "cannot process policy update")
	}

	existing, ok := state.Policies[id]
	if ok { // Policy with this ID already exists
		if pending {
			// Just replace policy in pending state
			state.Policies[id] = p
		} else {
			return errors.Wrap(existing.Update(s.vpp, p, state), "cannot update policy")
		}
	} else {
		// Create it in state
		state.Policies[id] = p
		if !pending {
			return errors.Wrap(p.Create(s.vpp, state), "cannot create policy")
		}
	}
	return nil
}

func (s *Server) handleActivePolicyRemove(msg *proto.ActivePolicyRemove, pending bool) (err error) {
	state := s.currentState(pending)
	id := PolicyID{
		Tier: msg.Id.Tier,
		Name: msg.Id.Name,
	}
	existing, ok := state.Policies[id]
	if !ok {
		s.log.Debugf("Received policy delete for Tier %s Name %s that doesn't exists", id.Tier, id.Name)
		return nil
	}
	if !pending {
		err = existing.Delete(s.vpp, state)
		if err != nil {
			return errors.Wrap(err, "error deleting policy")
		}
	}
	delete(state.Policies, id)
	return nil
}

func (s *Server) handleActiveProfileUpdate(msg *proto.ActiveProfileUpdate, pending bool) (err error) {
	s.log.Infof("Ignoring ActiveProfileUpdate")
	return nil
}

func (s *Server) handleActiveProfileRemove(msg *proto.ActiveProfileRemove, pending bool) (err error) {
	s.log.Infof("Ignoring ActiveProfileRemove")
	return nil
}

func (s *Server) handleHostEndpointUpdate(msg *proto.HostEndpointUpdate, pending bool) (err error) {
	s.log.Infof("Ignoring HostEndpointUpdate")
	return nil
}

func (s *Server) handleHostEndpointRemove(msg *proto.HostEndpointRemove, pending bool) (err error) {
	s.log.Infof("Ignoring HostEndpointRemove")
	return nil
}

func (s *Server) handleWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate, pending bool) (err error) {
	if pending {

	} else {

	}
	return nil
}

func (s *Server) handleWorkloadEndpointRemove(msg *proto.WorkloadEndpointRemove, pending bool) (err error) {
	if pending {

	} else {

	}
	return nil
}

func (s *Server) handleHostMetadataUpdate(msg *proto.HostMetadataUpdate, pending bool) (err error) {
	s.log.Infof("Ignoring HostMetadataUpdate")
	return nil
}

func (s *Server) handleHostMetadataRemove(msg *proto.HostMetadataRemove, pending bool) (err error) {
	s.log.Infof("Ignoring HostMetadataRemove")
	return nil
}

func (s *Server) handleIpamPoolUpdate(msg *proto.IPAMPoolUpdate, pending bool) (err error) {
	s.log.Infof("Ignoring IpamPoolUpdate")
	return nil
}

func (s *Server) handleIpamPoolRemove(msg *proto.IPAMPoolRemove, pending bool) (err error) {
	s.log.Infof("Ignoring IpamPoolRemove")
	return nil
}

func (s *Server) handleServiceAccountUpdate(msg *proto.ServiceAccountUpdate, pending bool) (err error) {
	s.log.Infof("Ignoring ServiceAccountUpdate")
	return nil
}

func (s *Server) handleServiceAccountRemove(msg *proto.ServiceAccountRemove, pending bool) (err error) {
	s.log.Infof("Ignoring ServiceAccountRemove")
	return nil
}

func (s *Server) handleNamespaceUpdate(msg *proto.NamespaceUpdate, pending bool) (err error) {
	s.log.Infof("Ignoring NamespaceUpdate")
	return nil
}

func (s *Server) handleNamespaceRemove(msg *proto.NamespaceRemove, pending bool) (err error) {
	s.log.Infof("Ignoring NamespaceRemove")
	return nil
}

// Reconciles the pending state with the configured state
func (s *Server) applyPendingState() (err error) {
	s.log.Infof("Reconciliating pending policy state with configured state")
	// Stupid algorithm for now, delete all that is in configured state, and then recreate everything
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

	s.configuredState = s.pendingState
	s.pendingState = NewPolicyState()
	for _, ipset := range s.configuredState.IPSets {
		err = ipset.Create(s.vpp)
		if err != nil {
			s.log.Warnf("error creating ipset: %v", err)
		}
	}
	for _, profile := range s.configuredState.Profiles {
		err = profile.Create(s.vpp, s.configuredState)
		if err != nil {
			s.log.Warnf("error creating profile: %v", err)
		}
	}
	for _, policy := range s.configuredState.Policies {
		err = policy.Create(s.vpp, s.configuredState)
		if err != nil {
			s.log.Warnf("error creating policy: %v", err)
		}
	}

	return nil
}
