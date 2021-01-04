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

package routing

import (
	"context"
	"fmt"
	"net"
	"reflect"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	agentCommon "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
)

func (s *Server) isMeshMode() bool {
	return *s.defaultBGPConf.NodeToNodeMeshEnabled
}

func nodeSpecCopy(calicoNode *calicov3.Node) *common.NodeState {
	calicoSpec := calicoNode.Spec
	spec := calicov3.NodeSpec{
		IPv4VXLANTunnelAddr: calicoSpec.IPv4VXLANTunnelAddr,
		VXLANTunnelMACAddr:  calicoSpec.VXLANTunnelMACAddr,
		OrchRefs:            append([]calicov3.OrchRef{}, calicoSpec.OrchRefs...),
	}
	if calicoSpec.BGP != nil {
		spec.BGP = &calicov3.NodeBGPSpec{
			IPv4Address:             calicoSpec.BGP.IPv4Address,
			IPv6Address:             calicoSpec.BGP.IPv6Address,
			IPv4IPIPTunnelAddr:      calicoSpec.BGP.IPv4IPIPTunnelAddr,
			RouteReflectorClusterID: calicoSpec.BGP.RouteReflectorClusterID,
		}
		if calicoSpec.BGP.ASNumber != nil {
			spec.BGP.ASNumber = new(numorstring.ASNumber)
			*spec.BGP.ASNumber = *calicoSpec.BGP.ASNumber
		}
	}
	calicoStatus := calicoNode.Status
	status := calicov3.NodeStatus{
		WireguardPublicKey: calicoStatus.WireguardPublicKey,
	}
	return &common.NodeState{
		Name:      calicoNode.Name,
		Spec:      spec,
		Status:    status,
		SweepFlag: false,
	}
}

func (s *Server) GetNodeByIp(addr net.IP) *common.NodeState {
	s.nodeStateLock.Lock()
	defer s.nodeStateLock.Unlock()
	nodename, found := s.nodeNamesByAddr[addr.String()]
	if !found {
		return nil
	}
	node, found := s.nodeStatesByName[nodename]
	if !found {
		return nil
	}
	return &node
}

func (s *Server) addNodeState(state *common.NodeState) {
	s.nodeStatesByName[state.Name] = *state
	nodeIP, _, err := net.ParseCIDR(state.Spec.BGP.IPv6Address)
	if err == nil {
		s.nodeNamesByAddr[nodeIP.String()] = state.Name
	}
	nodeIP, _, err = net.ParseCIDR(state.Spec.BGP.IPv4Address)
	if err == nil {
		s.nodeNamesByAddr[nodeIP.String()] = state.Name
	}
}
func (s *Server) delNodeState(nodename string) {
	node, found := s.nodeStatesByName[nodename]
	if found {
		nodeIP, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err == nil {
			delete(s.nodeNamesByAddr, nodeIP.String())
		}
		nodeIP, _, err = net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err == nil {
			delete(s.nodeNamesByAddr, nodeIP.String())
		}
	}
	delete(s.nodeStatesByName, nodename)
}

func (s *Server) initialNodeSync() (string, error) {
	s.nodeStateLock.Lock()
	defer s.nodeStateLock.Unlock()
	// TODO: Get and watch only ourselves if there is no mesh
	s.log.Info("Syncing nodes...")
	nodes, err := s.clientv3.Nodes().List(context.Background(), options.ListOptions{})
	if err != nil {
		return "", errors.Wrap(err, "error listing nodes")
	}
	for _, n := range s.nodeStatesByName {
		n.SweepFlag = true
	}
	for _, calicoNode := range nodes.Items {
		node := nodeSpecCopy(&calicoNode)
		shouldRestart, err := s.handleNodeUpdate(node, watch.Added)
		if err != nil {
			return "", errors.Wrap(err, "error handling node update")
		}
		if shouldRestart {
			return "", fmt.Errorf("Current node configuration changed, restarting")
		}
	}
	for _, node := range s.nodeStatesByName {
		if node.SweepFlag {
			shouldRestart, err := s.handleNodeUpdate(&node, watch.Deleted)
			if err != nil {
				return "", errors.Wrap(err, "error handling node update")
			}
			if shouldRestart {
				return "", fmt.Errorf("Current node configuration changed, restarting")
			}
		}
	}
	return nodes.ResourceVersion, nil
}

func (s *Server) watchNodes(initialResourceVersion string) error {
	var firstWatch = true
	for {
		resourceVersion, err := s.initialNodeSync()
		if err != nil {
			return err
		}
		/* if its the first time in the loop initialResourceVersion happened
		 * before the list in initialNodeSync */
		if firstWatch {
			resourceVersion = initialResourceVersion
			firstWatch = false
		}
		watcher, err := s.clientv3.Nodes().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: resourceVersion},
		)
		if err != nil {
			return errors.Wrap(err, "cannot watch nodes")
		}
	watch:
		for update := range watcher.ResultChan() {
			var calicoNode *calicov3.Node
			switch update.Type {
			case watch.Error:
				s.log.Infof("nodes watch returned an error")
				break watch
			case watch.Modified, watch.Added:
				calicoNode = update.Object.(*calicov3.Node)
			case watch.Deleted:
				calicoNode = update.Previous.(*calicov3.Node)
			}

			node := nodeSpecCopy(calicoNode)
			s.nodeStateLock.Lock()
			shouldRestart, err := s.handleNodeUpdate(node, update.Type)
			s.nodeStateLock.Unlock()
			if err != nil {
				return errors.Wrap(err, "error handling node update")
			}
			if shouldRestart {
				return fmt.Errorf("Current node configuration changed, restarting")
			}
		}
	}
}

// Returns true if the config of the current node has changed and requires a restart
// Sets node.SweepFlag to false if an existing node is added to allow mark and sweep
func (s *Server) handleNodeUpdate(node *common.NodeState, eventType watch.EventType) (shouldRestart bool, err error) {
	s.log.Debugf("Got node update: %s %s %+v", eventType, node.Name, node)
	if node.Name == config.NodeName {
		// No need to manage ourselves, but if we change we need to restart
		// and reconfigure
		shouldRestart = false
		if eventType == watch.Deleted {
			shouldRestart = true
		} else {
			old, found := s.nodeStatesByName[node.Name]
			if found {
				// Check that there were no changes, restart if our BGP config changed
				old.SweepFlag = false
				s.log.Tracef("node comparison: old:%+v new:%+v", old.Spec.BGP, node.Spec.BGP)
				shouldRestart = !reflect.DeepEqual(old.Spec.BGP, node.Spec.BGP)
			}
		}
		// Always update node state
		s.addNodeState(node)
		return shouldRestart, nil
	}

	// If the mesh is disabled, discard all updates that aren't on the current node
	if !s.isMeshMode() || node.Spec.BGP == nil { // No BGP config for this node
		return false, nil
	}
	// This ensures that nodes that don't have a BGP Spec are never present in the state map

	err = nil
	old, found := s.nodeStatesByName[node.Name]
	switch eventType {
	case watch.Error:
		// Shouldn't happen
		return false, fmt.Errorf("Node event error")
	case watch.Added, watch.Modified:
		if found {
			err = s.onNodeUpdated(&old, node)
		} else {
			err = s.onNodeAdded(node)
		}
		s.addNodeState(node)
	case watch.Deleted:
		// This assumes that the old spec and the new spec are identical.
		if found {
			err = s.onNodeDeleted(&old)
			s.delNodeState(node.Name)
		} else {
			return false, fmt.Errorf("Node to delete not found")
		}
	}
	return false, err
}

func (s *Server) getSpecAddresses(node *common.NodeState) (string, string) {
	nodeIP4 := ""
	nodeIP6 := ""
	if node.Spec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv4Address, err)
			nodeIP4 = ""
		} else {
			nodeIP4 = addr.String()
		}
	}
	if node.Spec.BGP.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv6Address, err)
			nodeIP6 = ""
		} else {
			nodeIP6 = addr.String()
		}
	}
	return nodeIP4, nodeIP6
}

func (s *Server) configureRemoteNodeSnat(node *common.NodeState, isAdd bool) {
	if node.Spec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv4Address, err)
		} else {
			err = s.vpp.CnatAddDelSnatPrefix(agentCommon.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				s.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
	if node.Spec.BGP.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv6Address, err)
		} else {
			err = s.vpp.CnatAddDelSnatPrefix(agentCommon.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				s.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
}

func (s *Server) getAsNumber(node *common.NodeState) uint32 {
	if node.Spec.BGP.ASNumber == nil {
		return uint32(*s.defaultBGPConf.ASNumber)
	} else {
		return uint32(*node.Spec.BGP.ASNumber)
	}
}

func (s *Server) onNodeDeleted(old *common.NodeState) error {
	s.configureRemoteNodeSnat(old, false /* isAdd */)
	v4IP, v6IP := s.getSpecAddresses(old)
	if v4IP != "" {
		err := s.deleteBGPPeer(v4IP)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", v4IP)
		}
	}
	if v6IP != "" {
		err := s.deleteBGPPeer(v6IP)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", v6IP)
		}
	}
	return nil
}

type ChangeType int

const (
	ChangeNone    ChangeType = iota
	ChangeSame    ChangeType = iota
	ChangeAdded   ChangeType = iota
	ChangeDeleted ChangeType = iota
	ChangeUpdated ChangeType = iota
)

func getStringChangeType(old, new string) ChangeType {
	if old == new && new == "" {
		return ChangeNone
	} else if old == new {
		return ChangeSame
	} else if old == "" {
		return ChangeAdded
	} else if new == "" {
		return ChangeDeleted
	} else {
		return ChangeUpdated
	}
}

func (s *Server) onNodeUpdatedByAddrFamily(oldAddr string, addr string, oldASN uint32, asNumber uint32) (err error) {
	// Compare IPs and ASN
	switch getStringChangeType(oldAddr, addr) {
	case ChangeNone:
		// Address family not configured
	case ChangeSame:
		// Check for ASN change
		if oldASN != asNumber {
			// Update peer
			err = s.updateBGPPeer(addr, asNumber)
			if err != nil {
				return errors.Wrapf(err, "error adding peer %s", addr)
			}
		}
		// Otherwise nothing to do for address family
	case ChangeAdded:
		err = s.addBGPPeer(addr, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", addr)
		}
	case ChangeDeleted:
		// Delete old neighbor
		err = s.deleteBGPPeer(oldAddr)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", oldAddr)
		}
	case ChangeUpdated:
		// IP change, delete and re-add neighbor
		err = s.deleteBGPPeer(oldAddr)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", oldAddr)
		}
		err = s.addBGPPeer(addr, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", addr)
		}
	}
	return nil
}

func (s *Server) onNodeUpdated(old *common.NodeState, node *common.NodeState) (err error) {
	s.log.Debugf("node comparison: old:%+v new:%+v", old.Spec.BGP, node.Spec.BGP)

	newASN := s.getAsNumber(node)
	oldASN := s.getAsNumber(old)
	newV4IP, newV6IP := s.getSpecAddresses(node)
	oldV4IP, oldV6IP := s.getSpecAddresses(old)

	err = s.onNodeUpdatedByAddrFamily(oldV4IP, newV4IP, oldASN, newASN)
	if err != nil {
		return errors.Wrapf(err, "error updating v4")
	}
	err = s.onNodeUpdatedByAddrFamily(oldV6IP, newV6IP, oldASN, newASN)
	if err != nil {
		return errors.Wrapf(err, "error updating v6")
	}

	if getStringChangeType(old.Status.WireguardPublicKey, node.Status.WireguardPublicKey) > ChangeSame {
		s.updateAllIPConnectivity()
	}

	if getStringChangeType(oldV4IP, newV4IP) > ChangeSame || getStringChangeType(oldV6IP, newV6IP) > ChangeSame {
		s.configureRemoteNodeSnat(old, false /* isAdd */)
		s.configureRemoteNodeSnat(node, true /* isAdd */)
	}

	old.SweepFlag = false
	return nil
}

func (s *Server) onNodeAdded(node *common.NodeState) (err error) {
	s.configureRemoteNodeSnat(node, true /* isAdd */)
	asNumber := s.getAsNumber(node)
	v4IP, v6IP := s.getSpecAddresses(node)
	if v4IP != "" {
		err = s.addBGPPeer(v4IP, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", v4IP)
		}
	}
	if v6IP != "" {
		err = s.addBGPPeer(v6IP, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", v6IP)
		}
	}
	return nil
}
