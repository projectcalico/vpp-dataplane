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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	felixConfig "github.com/projectcalico/calico/felix/config"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	FelixPluginSrcPath = "/bin/felix-api-proxy"
	FelixPluginDstPath = "/var/lib/calico/felix-plugins/felix-api-proxy"
)

type SyncState int

const (
	StateDisconnected SyncState = iota
	StateConnected
	StateSyncing
	StateInSync
)

type IfNetwork struct {
	ifName      string
	networkName string
}

// Server holds all the data required to configure the policies defined by felix in VPP
type Server struct {
	log *logrus.Entry
	vpp *vpplink.VppLink

	nodeBGPSpec *oldv3.NodeBGPSpec

	state         SyncState
	nextSeqNumber uint64

	endpointsLock       sync.Mutex
	endpointsInterfaces map[WorkloadEndpointID][]uint32

	idsNetworks map[*WorkloadEndpointID]string

	configuredState *PolicyState
	pendingState    *PolicyState

	/* failSafe policies allow traffic on some ports irrespective of the policy */
	failSafePolicy *Policy
	/* workloadToHost may drop traffic that goes from the pods to the host */
	workloadsToHostIPSet  *IPSet
	workloadsToHostPolicy *Policy
	/* always allow traffic coming from host to the pods (for healthchecks and so on) */
	allowFromHostPolicy *Policy
	/* allow traffic between uplink/tunnels and tap interfaces */
	allowToHostPolicy *Policy
	ip4               *net.IP
	ip6               *net.IP
	interfacesMap     map[string]interfaceDetails

	policyServerEventChan   chan common.CalicoVppEvent
	policyMultinetEventChan chan common.CalicoVppEvent
	networkDefinitions      map[string]*watchers.NetworkDefinition

	tunnelSwIfIndexes     map[uint32]bool
	tunnelSwIfIndexesLock sync.Mutex

	felixConfigReceived bool
	felixConfigChan     chan *felixConfig.Config
	felixConfig         *felixConfig.Config
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *oldv3.NodeBGPSpec) {
	ip4, ip6 := common.GetBGPSpecAddresses(nodeBGPSpec)
	s.ip4 = ip4
	s.ip6 = ip6
}

// NewServer creates a policy server
func NewPolicyServer(vpp *vpplink.VppLink, log *logrus.Entry) (*Server, error) {
	var err error

	server := &Server{
		log: log,
		vpp: vpp,

		state:         StateDisconnected,
		nextSeqNumber: 0,

		endpointsInterfaces: make(map[WorkloadEndpointID][]uint32),

		configuredState: NewPolicyState(),
		pendingState:    NewPolicyState(),

		policyServerEventChan:   make(chan common.CalicoVppEvent, common.ChanSize),
		policyMultinetEventChan: make(chan common.CalicoVppEvent, common.ChanSize),

		idsNetworks:        make(map[*WorkloadEndpointID]string),
		networkDefinitions: make(map[string]*watchers.NetworkDefinition),

		tunnelSwIfIndexes:   make(map[uint32]bool),
		felixConfigReceived: false,
		felixConfigChan:     make(chan *felixConfig.Config),
		felixConfig:         felixConfig.New(),
	}

	reg := common.RegisterHandler(server.policyServerEventChan, "policy server events")
	reg.ExpectEvents(
		common.PodAdded,
		common.PodDeleted,
		common.TunnelAdded,
		common.TunnelDeleted,
	)
	regM := common.RegisterHandler(server.policyMultinetEventChan, "policy server Multinet events")
	regM.ExpectEvents(
		common.NetAddedOrUpdated,
		common.NetDeleted,
		common.NetsSynced,
	)

	server.interfacesMap, err = server.mapTagToInterfaceDetails()
	if err != nil {
		return nil, errors.Wrapf(err, "error in mapping uplink to tap interfaces")
	}

	// Cleanup potentially left over socket
	err = os.RemoveAll(config.FelixDataplaneSocket)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not delete socket %s", config.FelixDataplaneSocket)
	}

	err = InstallFelixPlugin()
	if err != nil {
		return nil, errors.Wrap(err, "could not install felix plugin")
	}

	return server, nil
}

type interfaceDetails struct {
	tapIndex    uint32
	uplinkIndex uint32
	addresses   []string
}

func (s *Server) mapTagToInterfaceDetails() (tagIfDetails map[string]interfaceDetails, err error) {
	tagIfDetails = make(map[string]interfaceDetails)
	uplinkSwifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("main-")
	if err != nil {
		return nil, err
	}
	tapSwifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("host-")
	if err != nil {
		return nil, err
	}
	for intf, uplink := range uplinkSwifindexes {
		tap, found := tapSwifindexes["host-"+intf[5:]]
		if found {
			ip4adds, err := s.vpp.AddrList(uplink, false)
			if err != nil {
				return nil, err
			}
			ip6adds, err := s.vpp.AddrList(uplink, true)
			if err != nil {
				return nil, err
			}
			adds := append(ip4adds, ip6adds...)
			addresses := []string{}
			for _, add := range adds {
				addresses = append(addresses, add.IPNet.IP.String())
			}
			tagIfDetails[intf[5:]] = interfaceDetails{tap, uplink, addresses}
		} else {
			return nil, errors.Errorf("uplink interface %s not corresponding to a tap interface", uplink)
		}
	}
	return tagIfDetails, nil
}

func InstallFelixPlugin() (err error) {
	err = os.RemoveAll(FelixPluginDstPath)
	if err != nil {
		log.Warnf("Could not delete %s: %v", FelixPluginDstPath, err)
	}

	in, err := os.Open(FelixPluginSrcPath)
	if err != nil {
		return errors.Wrap(err, "cannot open felix plugin to copy")
	}
	defer in.Close()

	out, err := os.OpenFile(FelixPluginDstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return errors.Wrap(err, "cannot open felix plugin to write")
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = errors.Wrap(cerr, "cannot close felix plugin file")
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return errors.Wrap(err, "cannot copy data")
	}
	err = out.Sync()
	return errors.Wrapf(err, "could not sync felix plugin changes")
}

func (s *Server) getEndpointToHostAction() string {
	if s.felixConfig.DefaultEndpointToHostAction == "" {
		return "DROP"
	}
	return strings.ToUpper(s.felixConfig.DefaultEndpointToHostAction)
}

// workloadAdded is called by the CNI server when a container interface is created,
// either during startup when reconnecting the interfaces, or when a new pod is created
func (s *Server) workloadAdded(id *WorkloadEndpointID, swIfIndex uint32, containerIPs []*net.IPNet) {
	// TODO: Send WorkloadEndpointStatusUpdate to felix
	s.endpointsLock.Lock()
	defer s.endpointsLock.Unlock()

	intf, existing := s.endpointsInterfaces[*id]

	if existing {
		for _, exInt := range intf {
			if swIfIndex == exInt {
				return
			}
		}
		// VPP restarted and interfaces are being reconnected
		s.log.Warnf("workload endpoint changed interfaces, did VPP restart? %v %d -> %d", id, intf, swIfIndex)
		s.endpointsInterfaces[*id] = append(s.endpointsInterfaces[*id], swIfIndex)
	}

	s.log.Infof("policy(add) Workload id=%v swIfIndex=%d", id, swIfIndex)
	if s.endpointsInterfaces[*id] == nil {
		s.endpointsInterfaces[*id] = []uint32{swIfIndex}
	} else {
		s.endpointsInterfaces[*id] = append(s.endpointsInterfaces[*id], swIfIndex)
	}

	if s.state == StateInSync {
		s.log.Infof("creating wep in workloadadded?")
		wep, ok := s.configuredState.WorkloadEndpoints[*id]
		if !ok {
			s.log.Infof("not creating wep in workloadadded")
			// Nothing to configure
		} else {
			err := wep.Create(s.vpp, []uint32{swIfIndex}, s.configuredState, id.Network)
			if err != nil {
				s.log.Errorf("Error processing workload addition: %s", err)
			}
		}
	}
	// EndpointToHostAction
	if s.getEndpointToHostAction() == "DROP" {
		allMembers := []string{}
		for _, containerIP := range containerIPs {
			allMembers = append(allMembers, containerIP.IP.String())
		}
		s.workloadsToHostIPSet.AddMembers(allMembers, true, s.vpp)
	}
}

// WorkloadRemoved is called by the CNI server when the interface of a pod is deleted
func (s *Server) WorkloadRemoved(id *WorkloadEndpointID, containerIPs []*net.IPNet) {
	// TODO: Send WorkloadEndpointStatusRemove to felix
	s.endpointsLock.Lock()
	defer s.endpointsLock.Unlock()

	_, existing := s.endpointsInterfaces[*id]
	if !existing {
		s.log.Warnf("nonexistent workload endpoint removed %v", id)
		return
	}
	s.log.Infof("policy(del) workload id=%v", id)

	if s.state == StateInSync {
		wep, ok := s.configuredState.WorkloadEndpoints[*id]
		if !ok {
			// Nothing to clean up
		} else {
			err := wep.Delete(s.vpp)
			if err != nil {
				s.log.Errorf("Error processing workload removal: %s", err)
			}
		}
	}
	delete(s.endpointsInterfaces, *id)
	// EndpointToHostAction
	if s.getEndpointToHostAction() == "DROP" {
		allMembers := []string{}
		for _, containerIP := range containerIPs {
			allMembers = append(allMembers, containerIP.IP.String())
		}
		s.workloadsToHostIPSet.RemoveMembers(allMembers, true, s.vpp)
	}
}

func (s *Server) handlePolicyServerEvents(evt common.CalicoVppEvent) error {
	/* Note: we will only receive events we ask for when registering the chan */
	switch evt.Type {
	case common.PodAdded:
		podSpec := evt.New.(*storage.LocalPodSpec)
		swIfIndex := podSpec.TunTapSwIfIndex
		if swIfIndex == vpplink.InvalidID {
			swIfIndex = podSpec.MemifSwIfIndex
		}
		s.workloadAdded(&WorkloadEndpointID{
			OrchestratorID: podSpec.OrchestratorID,
			WorkloadID:     podSpec.WorkloadID,
			EndpointID:     podSpec.EndpointID,
			Network:        podSpec.NetworkName,
		}, swIfIndex, podSpec.GetContainerIps())
	case common.PodDeleted:
		podSpec := evt.Old.(*storage.LocalPodSpec)
		if podSpec != nil {
			s.WorkloadRemoved(&WorkloadEndpointID{
				OrchestratorID: podSpec.OrchestratorID,
				WorkloadID:     podSpec.WorkloadID,
				EndpointID:     podSpec.EndpointID,
				Network:        podSpec.NetworkName,
			}, podSpec.GetContainerIps())
		}
	case common.TunnelAdded:
		swIfIndex := evt.New.(uint32)

		s.tunnelSwIfIndexesLock.Lock()
		s.tunnelSwIfIndexes[swIfIndex] = true
		s.tunnelSwIfIndexesLock.Unlock()

		var pending bool
		if s.state == StateSyncing || s.state == StateConnected {
			pending = true
		} else if s.state == StateInSync {
			pending = false
		} else {
			return fmt.Errorf("Got tunnel %d add but not in syncing or synced state", swIfIndex)
		}
		state := s.currentState(pending)
		for _, h := range state.HostEndpoints {
			h.handleTunnelChange(swIfIndex, true /* isAdd */, pending)
		}
	case common.TunnelDeleted:
		var pending bool

		swIfIndex := evt.Old.(uint32)

		s.tunnelSwIfIndexesLock.Lock()
		delete(s.tunnelSwIfIndexes, swIfIndex)
		s.tunnelSwIfIndexesLock.Unlock()

		if s.state == StateSyncing || s.state == StateConnected {
			pending = true
		} else if s.state == StateInSync {
			pending = false
		} else {
			return fmt.Errorf("Got tunnel %d del but not in syncing or synced state", swIfIndex)
		}
		state := s.currentState(pending)
		for _, h := range state.HostEndpoints {
			h.handleTunnelChange(swIfIndex, false /* isAdd */, pending)
		}
	}
	return nil
}

// Serve runs the policy server
func (s *Server) ServePolicy(t *tomb.Tomb) error {
	s.log.Info("Starting policy server")

	if !config.EnablePolicies {
		s.log.Warn("Policies disabled, policy server will not configure VPP")
	}

	listener, err := net.Listen("unix", config.FelixDataplaneSocket)
	if err != nil {
		return errors.Wrapf(err, "Could not bind to unix://%s", config.FelixDataplaneSocket)
	}
	defer func() {
		listener.Close()
		os.RemoveAll(config.FelixDataplaneSocket)
	}()

	err = s.createAllowFromHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createAllowFromHostPolicy")
	}
	err = s.createEndpointToHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createEndpointToHostPolicy")
	}
	err = s.createAllowToHostPolicy()
	if err != nil {
		return errors.Wrap(err, "Error in createAllowToHostPolicy")
	}
	err = s.createFailSafePolicies()
	if err != nil {
		return errors.Wrap(err, "Error in createFailSafePolicies")
	}
	if config.MultinetEnabled {
		netsSynced := make(chan bool)
		go func() {
			for t.Alive() {
				event := <-s.policyMultinetEventChan
				switch event.Type {
				case common.NetsSynced:
					netsSynced <- true
				case common.NetAddedOrUpdated:
					netDef := event.New.(*watchers.NetworkDefinition)
					s.networkDefinitions[netDef.Name] = netDef
				case common.NetDeleted:
					netDef := event.Old.(*watchers.NetworkDefinition)
					delete(s.networkDefinitions, netDef.Name)
				}
			}
		}()
		<-netsSynced
	}
	for {
		s.state = StateDisconnected
		// Accept only one connection
		conn, err := listener.Accept()
		if err != nil {
			return errors.Wrap(err, "cannot accept policy client connection")
		}
		s.log.Infof("Accepted connection from felix")
		s.state = StateConnected

		felixUpdates := s.MessageReader(conn)
	innerLoop:
		for {
			select {
			case <-t.Dying():
				s.log.Infof("Policy server exiting")
				err = conn.Close()
				if err != nil {
					s.log.WithError(err).Warn("Error closing unix connection to felix API proxy")
				}
				s.log.Infof("Waiting for SyncPolicy to stop...")
				return nil
			case evt := <-s.policyServerEventChan:
				err = s.handlePolicyServerEvents(evt)
				if err != nil {
					s.log.WithError(err).Warn("Error handling PolicyServerEvents")
				}
			// <-felixUpdates & handleFelixUpdate does the bulk of the policy sync job. It starts by reconciling the current
			// configured state in VPP (empty at first) with what is sent by felix, and once both are in
			// sync, it keeps processing felix updates. It also sends endpoint updates to felix when the
			// CNI component adds or deletes container interfaces.
			case msg, ok := <-felixUpdates:
				if !ok {
					s.log.Debugf("Felix MessageReader closed")
					break innerLoop
				}
				err = s.handleFelixUpdate(msg)
				if err != nil {
					s.log.WithError(err).Error("Error processing update from felix, restarting")
					// TODO: Restart VPP as well? State is left over there...
					break innerLoop
				}
			}
		}
		err = conn.Close()
		if err != nil {
			s.log.WithError(err).Warn("Error closing unix connection to felix API proxy")
		}
		s.log.Infof("SyncPolicy exited, reconnecting to felix")
	}
}

func (s *Server) handleFelixUpdate(msg interface{}) (err error) {
	s.log.Debugf("Got message from felix: %+v", msg)
	switch m := msg.(type) {
	case *proto.ConfigUpdate:
		err = s.handleConfigUpdate(m)
	case *proto.InSync:
		err = s.handleInSync(m)
	default:
		if !config.EnablePolicies {
			// Skip processing of policy messages
			return nil
		}
		var pending bool
		if s.state == StateSyncing {
			pending = true
		} else if s.state == StateInSync {
			pending = false
		} else {
			return fmt.Errorf("Got message %+v but not in syncing or synced state", m)
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
		case *proto.GlobalBGPConfigUpdate:
			err = s.handleGlobalBGPConfigUpdate(m, pending)
		default:
			s.log.Warnf("Unhandled message from felix: %v", m)
		}
	}
	return err
}

func (s *Server) currentState(pending bool) *PolicyState {
	if pending {
		return s.pendingState
	}
	return s.configuredState
}

func (s *Server) WaitForFelixConfig() *felixConfig.Config {
	return <-s.felixConfigChan
}

func safeParseBool(str string, onErr bool) bool {
	parsed, err := strconv.ParseBool(str)
	if err != nil {
		return onErr
	}
	return parsed
}

func safeParseInt(str string, onErr int) int {
	parsed, err := strconv.Atoi(str)
	if err != nil {
		return onErr
	}
	return parsed
}

/**
 * remove add the fields of type `file` we dont need and for which the
 * parsing will fail
 *
 * This logic is extracted from `loadParams` in [0]
 * [0] projectcalico/felix/config/config_params.go:Config
 * it applies the regex only on the reflected struct definition,
 * not on the live data.
 *
 **/
func removeFelixConfigFileField(rawData map[string]string) {
	config := felixConfig.Config{}
	kind := reflect.TypeOf(config)
	metaRegexp := regexp.MustCompile(`^([^;(]+)(?:\(([^)]*)\))?;` +
		`([^;]*)(?:;` +
		`([^;]*))?$`)
	for ii := 0; ii < kind.NumField(); ii++ {
		field := kind.Field(ii)
		tag := field.Tag.Get("config")
		if tag == "" {
			continue
		}
		captures := metaRegexp.FindStringSubmatch(tag)
		kind := captures[1] // Type: "int|oneof|bool|port-list|..."
		if kind == "file" {
			delete(rawData, field.Name)
		}
	}
}

// the msg.Config map[string]string is the serialized object
// projectcalico/felix/config/config_params.go:Config
func (s *Server) handleConfigUpdate(msg *proto.ConfigUpdate) (err error) {
	if s.state != StateConnected {
		return fmt.Errorf("Received ConfigUpdate but server is not in Connected state! state: %v", s.state)
	}
	s.log.Infof("Got config from felix: %+v", msg)
	s.state = StateSyncing

	oldFelixConfig := s.felixConfig
	removeFelixConfigFileField(msg.Config)
	s.felixConfig = felixConfig.New()
	_, err = s.felixConfig.UpdateFrom(msg.Config, felixConfig.InternalOverride)
	if err != nil {
		return err
	}
	changed := !reflect.DeepEqual(oldFelixConfig.RawValues(), s.felixConfig.RawValues())

	// Note: This function will be called each time the Felix config changes.
	// If we start handling config settings that require agent restart,
	// we'll need to add a mechanism for that
	if !s.felixConfigReceived {
		s.felixConfigReceived = true
		s.felixConfigChan <- s.felixConfig
	}

	if !changed {
		return nil
	}

	common.SendEvent(common.CalicoVppEvent{
		Type: common.FelixConfChanged,
		New:  s.felixConfig,
		Old:  oldFelixConfig,
	})

	if s.felixConfig.DefaultEndpointToHostAction != oldFelixConfig.DefaultEndpointToHostAction {
		s.log.Infof("TODO : default endpoint to host action changed")
	}

	if !protoPortListEqual(s.felixConfig.FailsafeInboundHostPorts, oldFelixConfig.FailsafeInboundHostPorts) ||
		!protoPortListEqual(s.felixConfig.FailsafeOutboundHostPorts, oldFelixConfig.FailsafeOutboundHostPorts) {
		err = s.createFailSafePolicies()
		if err != nil {
			return err
		}
	}

	return nil
}

func protoPortListEqual(a, b []felixConfig.ProtoPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i, elemA := range a {
		elemB := b[i]
		if elemA.Net != elemB.Net {
			return false
		}
		if elemA.Protocol != elemB.Protocol {
			return false
		}
		if elemA.Port != elemB.Port {
			return false
		}
	}
	return true
}

func (s *Server) handleInSync(msg *proto.InSync) (err error) {
	if s.state != StateSyncing {
		return fmt.Errorf("Received InSync but state was not syncing")
	}
	s.endpointsLock.Lock()
	defer s.endpointsLock.Unlock()

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
	log.Debugf("Handled Ipset Update pending=%t id=%s %s", pending, msg.GetId(), ips)
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
	log.Debugf("Handled Ipset delta Update pending=%t id=%s %s", pending, msg.GetId(), ips)
	return nil
}

func (s *Server) handleIpsetRemove(msg *proto.IPSetRemove, pending bool) (err error) {
	state := s.currentState(pending)
	ips, ok := state.IPSets[msg.GetId()]
	if !ok {
		s.log.Warnf("Received ipset delete for ID %s that doesn't exists", msg.GetId())
		return nil
	}
	if !pending {
		err = ips.Delete(s.vpp)
		if err != nil {
			return errors.Wrapf(err, "cannot delete ipset %s", msg.GetId())
		}
	}
	log.Debugf("Handled Ipset remove pending=%t id=%s %s", pending, msg.GetId(), ips)
	delete(state.IPSets, msg.GetId())
	return nil
}

func (s *Server) handleActivePolicyUpdate(msg *proto.ActivePolicyUpdate, pending bool) (err error) {
	state := s.currentState(pending)
	id := PolicyID{
		Tier: msg.Id.Tier,
		Name: msg.Id.Name,
	}
	p, err := fromProtoPolicy(msg.Policy, "")
	if err != nil {
		return errors.Wrapf(err, "cannot process policy update")
	}

	log.Infof("Handling ActivePolicyUpdate pending=%t id=%s %s", pending, id, p)
	existing, ok := state.Policies[id]
	if ok { // Policy with this ID already exists
		if pending {
			// Just replace policy in pending state
			state.Policies[id] = p
		} else {
			err := existing.Update(s.vpp, p, state)
			if err != nil {
				return errors.Wrap(err, "cannot update policy")
			}
		}
	} else {
		// Create it in state
		state.Policies[id] = p
		if !pending {
			err := p.Create(s.vpp, state)
			if err != nil {
				return errors.Wrap(err, "cannot create policy")
			}
		}
	}

	for network := range s.networkDefinitions {
		p, err := fromProtoPolicy(msg.Policy, network)
		if err != nil {
			return errors.Wrapf(err, "cannot process policy update")
		}

		log.Infof("Handling ActivePolicyUpdate pending=%t id=%s %s", pending, id, p)
		_, ok := state.multinetPolicies[network]
		if !ok {
			state.multinetPolicies[network] = make(map[PolicyID]*Policy)
		}
		existing, ok := state.multinetPolicies[network][id]
		if ok { // Policy with this ID already exists
			if pending {
				// Just replace policy in pending state
				state.multinetPolicies[network][id] = p
			} else {
				err := existing.Update(s.vpp, p, state)
				if err != nil {
					return errors.Wrap(err, "cannot update policy")
				}
			}
		} else {
			// Create it in state
			state.multinetPolicies[network][id] = p
			if !pending {
				err := p.Create(s.vpp, state)
				if err != nil {
					return errors.Wrap(err, "cannot create policy")
				}
			}
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
	log.Infof("policy(del) Handling ActivePolicyRemove pending=%t id=%s", pending, id)

	existing, ok := state.Policies[id]
	if !ok {
		s.log.Warnf("Received policy delete for Tier %s Name %s that doesn't exists", id.Tier, id.Name)
		return nil
	}
	if !pending {
		err = existing.Delete(s.vpp, state)
		if err != nil {
			return errors.Wrap(err, "error deleting policy")
		}
	}
	delete(state.Policies, id)
	for network := range state.multinetPolicies {
		existing, ok := state.multinetPolicies[network][id]
		if !ok {
			s.log.Warnf("Received policy delete for Tier %s Name %s that doesn't exists", id.Tier, id.Name)
			return nil
		}
		if !pending {
			err = existing.Delete(s.vpp, state)
			if err != nil {
				return errors.Wrap(err, "error deleting policy")
			}
		}
		delete(state.multinetPolicies[network], id)
	}
	return nil
}

func (s *Server) handleActiveProfileUpdate(msg *proto.ActiveProfileUpdate, pending bool) (err error) {
	state := s.currentState(pending)
	id := msg.Id.Name
	p, err := fromProtoProfile(msg.Profile)
	if err != nil {
		return errors.Wrapf(err, "cannot process profile update")
	}

	existing, ok := state.Profiles[id]
	if ok { // Policy with this ID already exists
		if pending {
			// Just replace policy in pending state
			state.Profiles[id] = p
		} else {
			err := existing.Update(s.vpp, p, state)
			if err != nil {
				return errors.Wrap(err, "cannot update profile")
			}
		}
	} else {
		// Create it in state
		state.Profiles[id] = p
		if !pending {
			err := p.Create(s.vpp, state)
			if err != nil {
				return errors.Wrap(err, "cannot create profile")
			}
		}
	}
	log.Infof("policy(upd) Handled Profile Update pending=%t id=%s existing=%s new=%s", pending, id, existing, p)
	return nil
}

func (s *Server) handleActiveProfileRemove(msg *proto.ActiveProfileRemove, pending bool) (err error) {
	state := s.currentState(pending)
	id := msg.Id.Name
	existing, ok := state.Profiles[id]
	if !ok {
		s.log.Warnf("Received profile delete for Name %s that doesn't exists", id)
		return nil
	}
	if !pending {
		err = existing.Delete(s.vpp, state)
		if err != nil {
			return errors.Wrap(err, "error deleting profile")
		}
	}
	log.Infof("policy(del) Handled Profile Remove pending=%t id=%s policy=%s", pending, id, existing)
	delete(state.Profiles, id)
	return nil
}

func (s *Server) getAllTunnelSwIfIndexes() (swIfIndexes []uint32) {
	s.tunnelSwIfIndexesLock.Lock()
	defer s.tunnelSwIfIndexesLock.Unlock()

	swIfIndexes = make([]uint32, 0)
	for k, _ := range s.tunnelSwIfIndexes {
		swIfIndexes = append(swIfIndexes, k)
	}
	return swIfIndexes
}

func (s *Server) handleHostEndpointUpdate(msg *proto.HostEndpointUpdate, pending bool) (err error) {
	state := s.currentState(pending)
	id := fromProtoHostEndpointID(msg.Id)
	hep := fromProtoHostEndpoint(msg.Endpoint, s)
	if hep.InterfaceName != "" && hep.InterfaceName != "*" {
		interfaceDetails, found := s.interfacesMap[hep.InterfaceName]
		if found {
			hep.UplinkSwIfIndexes = append(hep.UplinkSwIfIndexes, interfaceDetails.uplinkIndex)
			hep.TapSwIfIndexes = append(hep.TapSwIfIndexes, interfaceDetails.tapIndex)
		} else {
			s.log.Errorf("cannot find host endpoint: interface named %s does not exist", hep.InterfaceName)
		}
	} else if hep.InterfaceName == "" && hep.expectedIPs != nil {
		for _, existingIf := range s.interfacesMap {
		interfaceFound:
			for _, address := range existingIf.addresses {
				for _, expectedIP := range hep.expectedIPs {
					if address == expectedIP {
						hep.UplinkSwIfIndexes = append(hep.UplinkSwIfIndexes, existingIf.uplinkIndex)
						hep.TapSwIfIndexes = append(hep.TapSwIfIndexes, existingIf.tapIndex)
						break interfaceFound
					}
				}
			}
		}
	} else if hep.InterfaceName == "*" {
		for _, interfaceDetails := range s.interfacesMap {
			hep.UplinkSwIfIndexes = append(hep.UplinkSwIfIndexes, interfaceDetails.uplinkIndex)
			hep.TapSwIfIndexes = append(hep.TapSwIfIndexes, interfaceDetails.tapIndex)
		}
	}
	hep.TunnelSwIfIndexes = s.getAllTunnelSwIfIndexes()
	if len(hep.UplinkSwIfIndexes) == 0 || len(hep.TapSwIfIndexes) == 0 {
		s.log.Errorf("No interface for host endpoint id=%s hep=%s", id.EndpointID, hep.String())
		return nil
	}

	existing, found := state.HostEndpoints[*id]
	if found {
		if pending {
			hep.ownPolicies = existing.ownPolicies
			hep.currentForwardConf = existing.currentForwardConf
			state.HostEndpoints[*id] = hep
		} else {
			err := existing.Update(s.vpp, hep, state)
			if err != nil {
				return errors.Wrap(err, "cannot update host endpoint")
			}
		}
		s.log.Infof("policy(upd) Updating host endpoint id=%s found=%t existing=%s new=%s", *id, found, existing, hep)
	} else {
		state.HostEndpoints[*id] = hep
		if !pending {
			err := hep.Create(s.vpp, state)
			if err != nil {
				return errors.Wrap(err, "cannot create host endpoint")
			}
		}
		s.log.Infof("policy(add) Updating host endpoint id=%s found=%t new=%s", *id, found, hep)
	}
	return nil
}

func (s *Server) handleHostEndpointRemove(msg *proto.HostEndpointRemove, pending bool) (err error) {
	state := s.currentState(pending)
	id := fromProtoHostEndpointID(msg.Id)
	existing, ok := state.HostEndpoints[*id]
	if !ok {
		s.log.Warnf("Received host endpoint delete for id=%s that doesn't exists", id)
		return nil
	}
	if !pending && len(existing.UplinkSwIfIndexes) != 0 {
		err = existing.Delete(s.vpp, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "error deleting host endpoint")
		}
	}
	log.Infof("policy(del) Handled Host Endpoint Remove pending=%t id=%s %s", pending, id, existing)
	delete(state.HostEndpoints, *id)
	return nil
}

func (s *Server) getAllWorkloadIds(msg *proto.WorkloadEndpointUpdate) map[string]*WorkloadEndpointID {
	id := fromProtoEndpointID(msg.Id)
	idsNetworks := map[string]*WorkloadEndpointID{"": id}
	netStatusesJson, found := msg.Endpoint.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !found {
		log.Infof("no network status for pod, no multiple networks")
	} else {
		var netStatuses []nettypes.NetworkStatus
		err := json.Unmarshal([]byte(netStatusesJson), &netStatuses)
		if err != nil {
			log.Error(err)
		}
		for idx := range netStatuses {
			for netDefName, netDef := range s.networkDefinitions {
				if netStatuses[idx].Name == netDef.Nad {
					id := &WorkloadEndpointID{OrchestratorID: id.OrchestratorID, WorkloadID: id.WorkloadID, EndpointID: id.EndpointID, Network: netDefName}
					idsNetworks[id.Network] = id
				}
			}
		}
	}
	return idsNetworks
}

func (s *Server) handleWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate, pending bool) (err error) {
	s.endpointsLock.Lock()
	defer s.endpointsLock.Unlock()

	state := s.currentState(pending)
	idsNetworks := s.getAllWorkloadIds(msg)
	for _, id := range idsNetworks {
		wep := fromProtoWorkload(msg.Endpoint, s)
		existing, found := state.WorkloadEndpoints[*id]
		swIfIndex, swIfIndexFound := s.endpointsInterfaces[*id]

		if found {
			if pending || !swIfIndexFound {
				state.WorkloadEndpoints[*id] = wep
				log.Infof("policy(upd) Workload Endpoint Update pending=%t id=%s existing=%s new=%s swIf=??", pending, *id, existing, wep)
			} else {
				err := existing.Update(s.vpp, wep, state, id.Network)
				if err != nil {
					return errors.Wrap(err, "cannot update workload endpoint")
				}
				log.Infof("policy(upd) Workload Endpoint Update pending=%t id=%s existing=%s new=%s swIf=%d", pending, *id, existing, wep, swIfIndex)
			}
		} else {
			state.WorkloadEndpoints[*id] = wep
			if !pending && swIfIndexFound {
				err := wep.Create(s.vpp, swIfIndex, state, id.Network)
				if err != nil {
					return errors.Wrap(err, "cannot create workload endpoint")
				}
				log.Infof("policy(add) Workload Endpoint add pending=%t id=%s new=%s swIf=%d", pending, *id, wep, swIfIndex)
			} else {
				log.Infof("policy(add) Workload Endpoint add pending=%t id=%s new=%s swIf=??", pending, *id, wep)
			}
		}
	}
	return nil
}

func (s *Server) handleWorkloadEndpointRemove(msg *proto.WorkloadEndpointRemove, pending bool) (err error) {
	s.endpointsLock.Lock()
	defer s.endpointsLock.Unlock()

	state := s.currentState(pending)
	id := fromProtoEndpointID(msg.Id)
	existing, ok := state.WorkloadEndpoints[*id]
	if !ok {
		s.log.Warnf("Received workload endpoint delete for %v that doesn't exists", id)
		return nil
	}
	if !pending && len(existing.SwIfIndex) != 0 {
		err = existing.Delete(s.vpp)
		if err != nil {
			return errors.Wrap(err, "error deleting workload endpoint")
		}
	}
	log.Infof("policy(del) Handled Workload Endpoint Remove pending=%t id=%s existing=%s", pending, *id, existing)
	delete(state.WorkloadEndpoints, *id)
	for existingId := range state.WorkloadEndpoints {
		if existingId.OrchestratorID == id.OrchestratorID && existingId.WorkloadID == id.WorkloadID {
			if !pending && len(existing.SwIfIndex) != 0 {
				err = existing.Delete(s.vpp)
				if err != nil {
					return errors.Wrap(err, "error deleting workload endpoint")
				}
			}
			log.Infof("policy(del) Handled Workload Endpoint Remove pending=%t id=%s existing=%s", pending, existingId, existing)
			delete(state.WorkloadEndpoints, existingId)
		}
	}
	return nil
}

func (s *Server) handleHostMetadataUpdate(msg *proto.HostMetadataUpdate, pending bool) (err error) {
	s.log.Debugf("Ignoring HostMetadataUpdate")
	return nil
}

func (s *Server) handleHostMetadataRemove(msg *proto.HostMetadataRemove, pending bool) (err error) {
	s.log.Debugf("Ignoring HostMetadataRemove")
	return nil
}

func (s *Server) handleIpamPoolUpdate(msg *proto.IPAMPoolUpdate, pending bool) (err error) {
	s.log.Debugf("Ignoring IpamPoolUpdate")
	return nil
}

func (s *Server) handleIpamPoolRemove(msg *proto.IPAMPoolRemove, pending bool) (err error) {
	s.log.Debugf("Ignoring IpamPoolRemove")
	return nil
}

func (s *Server) handleServiceAccountUpdate(msg *proto.ServiceAccountUpdate, pending bool) (err error) {
	s.log.Debugf("Ignoring ServiceAccountUpdate")
	return nil
}

func (s *Server) handleServiceAccountRemove(msg *proto.ServiceAccountRemove, pending bool) (err error) {
	s.log.Debugf("Ignoring ServiceAccountRemove")
	return nil
}

func (s *Server) handleNamespaceUpdate(msg *proto.NamespaceUpdate, pending bool) (err error) {
	s.log.Debugf("Ignoring NamespaceUpdate")
	return nil
}

func (s *Server) handleNamespaceRemove(msg *proto.NamespaceRemove, pending bool) (err error) {
	s.log.Debugf("Ignoring NamespaceRemove")
	return nil
}

func (s *Server) handleGlobalBGPConfigUpdate(msg *proto.GlobalBGPConfigUpdate, pending bool) (err error) {
	s.log.Infof("Got GlobalBGPConfigUpdate")
	common.SendEvent(common.CalicoVppEvent{
		Type: common.BGPConfChanged,
	})
	return nil
}

// Reconciles the pending state with the configured state
func (s *Server) applyPendingState() (err error) {
	s.log.Infof("Reconciliating pending policy state with configured state")
	// Stupid algorithm for now, delete all that is in configured state, and then recreate everything
	for _, wep := range s.configuredState.WorkloadEndpoints {
		if len(wep.SwIfIndex) != 0 {
			err = wep.Delete(s.vpp)
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
	for _, policyMap := range s.configuredState.multinetPolicies {
		for _, policy := range policyMap {
			err = policy.Delete(s.vpp, s.configuredState)
			if err != nil {
				s.log.Warnf("error deleting policy: %v", err)
			}
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
			err = hep.Delete(s.vpp, s.configuredState)
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
	for _, policyMap := range s.configuredState.multinetPolicies {
		for _, policy := range policyMap {
			err = policy.Create(s.vpp, s.configuredState)
			if err != nil {
				return errors.Wrap(err, "error creating policy")
			}
		}
	}
	for id, wep := range s.configuredState.WorkloadEndpoints {
		intf, intfFound := s.endpointsInterfaces[id]
		if intfFound {
			err = wep.Create(s.vpp, intf, s.configuredState, id.Network)
			if err != nil {
				return errors.Wrap(err, "cannot configure workload endpoint")
			}
		}
	}
	for _, hep := range s.configuredState.HostEndpoints {
		err = hep.Create(s.vpp, s.configuredState)
		if err != nil {
			return errors.Wrap(err, "cannot create host endpoint")
		}
	}
	s.log.Infof("Reconciliation done")
	return nil
}

func (s *Server) createAllowToHostPolicy() (err error) {
	s.log.Infof("Creating policy to allow traffic to host that is applied on uplink")
	r_in := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowtohost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			DstNet: []net.IPNet{},
		},
	}
	r_out := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowtohost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			SrcNet: []net.IPNet{},
		},
	}
	if s.ip4 != nil {
		r_in.Rule.DstNet = append(r_in.Rule.DstNet, *common.FullyQualified(*s.ip4))
		r_out.Rule.SrcNet = append(r_out.Rule.SrcNet, *common.FullyQualified(*s.ip4))
	}
	if s.ip6 != nil {
		r_in.Rule.DstNet = append(r_in.Rule.DstNet, *common.FullyQualified(*s.ip6))
		r_out.Rule.SrcNet = append(r_out.Rule.SrcNet, *common.FullyQualified(*s.ip6))
	}

	s.allowToHostPolicy = &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	s.allowToHostPolicy.InboundRules = append(s.allowToHostPolicy.InboundRules, r_out)
	s.allowToHostPolicy.OutboundRules = append(s.allowToHostPolicy.OutboundRules, r_in)
	err = s.allowToHostPolicy.Create(s.vpp, nil)
	return errors.Wrap(err, "cannot create policy to allow traffic to host")
}

func (s *Server) createAllowFromHostPolicy() (err error) {
	s.log.Infof("Creating policy to allow traffic from host with ingress policies")
	r := &Rule{
		VppID:  types.InvalidID,
		RuleID: "calicovpp-internal-allowfromhost",
		Rule: &types.Rule{
			Action: types.ActionAllow,
			SrcNet: []net.IPNet{},
		},
	}
	if s.ip4 != nil {
		r.Rule.SrcNet = append(r.Rule.SrcNet, *common.FullyQualified(*s.ip4))
	}
	if s.ip6 != nil {
		r.Rule.SrcNet = append(r.Rule.SrcNet, *common.FullyQualified(*s.ip6))
	}

	s.allowFromHostPolicy = &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	s.allowFromHostPolicy.InboundRules = append(s.allowFromHostPolicy.InboundRules, r)
	err = s.allowFromHostPolicy.Create(s.vpp, nil)
	return errors.Wrap(err, "cannot create policy to allow traffic from host")
}

func (s *Server) createEndpointToHostPolicy( /*may be return*/ ) (err error) {
	pol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	r_deny_workloads := &Rule{
		VppID: types.InvalidID,
		Rule: &types.Rule{
			Action: types.ActionDeny,
		},
		SrcIPSetNames: []string{"ipset1"},
	}
	ipset := NewIPSet()
	ps := PolicyState{IPSets: map[string]*IPSet{"ipset1": ipset}}
	ipset.Create(s.vpp)
	pol.InboundRules = append(pol.InboundRules, r_deny_workloads)
	err = pol.Create(s.vpp, &ps)
	if err != nil {
		return err
	}
	s.workloadsToHostIPSet = ipset
	s.workloadsToHostPolicy = pol

	r := &Rule{
		VppID: types.InvalidID,
		Rule: &types.Rule{
			Action: types.ActionAllow,
		},
	}
	pol = &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}
	pol.InboundRules = append(pol.InboundRules, r)
	err = pol.Create(s.vpp, &ps)
	if err != nil {
		return err
	}
	conf := types.NewInterfaceConfig()
	conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, s.workloadsToHostPolicy.VppID)
	conf.IngressPolicyIDs = append(conf.IngressPolicyIDs, pol.VppID)
	swifindexes, err := s.vpp.SearchInterfacesWithTagPrefix("host-") // tap interfaces
	if err != nil {
		s.log.Error(err)
	}
	for _, swifindex := range swifindexes {
		err = s.vpp.ConfigurePolicies(uint32(swifindex), conf)
		if err != nil {
			s.log.Error("cannot create policy to drop traffic to host")
		}
	}
	return nil
}

func (s *Server) createFailSafePolicies() (err error) {
	failSafePol := &Policy{
		Policy: &types.Policy{},
		VppID:  types.InvalidID,
	}

	fihp := s.felixConfig.FailsafeInboundHostPorts
	if len(fihp) == 0 {
		fihp = append(fihp,
			felixConfig.ProtoPort{Protocol: "tcp", Port: 22},
			felixConfig.ProtoPort{Protocol: "udp", Port: 68},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 179},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 2379},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 2380},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 5473},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 6443},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 6666},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 6667},
		)
	}
	failSafeInboundRules, err := getfailSafeRules(fihp)
	if err != nil {
		return err
	}

	fohp := s.felixConfig.FailsafeOutboundHostPorts
	if len(fohp) == 0 {
		fihp = append(fihp,
			felixConfig.ProtoPort{Protocol: "udp", Port: 53},
			felixConfig.ProtoPort{Protocol: "udp", Port: 67},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 179},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 2379},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 2380},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 5473},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 6443},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 6666},
			felixConfig.ProtoPort{Protocol: "tcp", Port: 6667},
		)
	}
	failSafeOutboundRules, err := getfailSafeRules(fohp)
	if err != nil {
		return err
	}

	failSafePol.InboundRules = failSafeInboundRules
	failSafePol.OutboundRules = failSafeOutboundRules
	err = failSafePol.Create(s.vpp, nil)
	if err != nil {
		return err
	}
	s.failSafePolicy = failSafePol
	return nil
}

func getProtocolRules(protocolName string, failSafe []felixConfig.ProtoPort) (*Rule, error) {
	portRanges := []types.PortRange{}

	for _, protoPort := range failSafe {
		if protoPort.Protocol == protocolName {
			portRanges = append(portRanges, types.PortRange{
				First: protoPort.Port,
				Last:  protoPort.Port,
			})
		}
	}
	protocol, err := parseProtocol(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: protocolName}})
	if err != nil {
		return nil, err
	}
	r_failsafe := &Rule{
		VppID:  types.InvalidID,
		RuleID: "failsafe" + protocolName,
		Rule: &types.Rule{
			Action:       types.ActionAllow,
			DstPortRange: portRanges,
			Filters: []types.RuleFilter{{
				ShouldMatch: true,
				Type:        types.CapoFilterProto,
				Value:       int(protocol),
			}},
		},
	}
	return r_failsafe, nil
}

func getfailSafeRules(failSafe []felixConfig.ProtoPort) ([]*Rule, error) {
	r_failsafe_tcp, err := getProtocolRules("tcp", failSafe)
	if err != nil {
		return nil, errors.Errorf("failsafe has wrong format")
	}
	r_failsafe_udp, err := getProtocolRules("udp", failSafe)
	if err != nil {
		return nil, errors.Errorf("failsafe has wrong format")
	}
	return []*Rule{r_failsafe_tcp, r_failsafe_udp}, nil
}
