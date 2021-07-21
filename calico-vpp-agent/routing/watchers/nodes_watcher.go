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

package watchers

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	agentCommon "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/sirupsen/logrus"
)

type NodeWatcher struct {
	*common.RoutingData
	log *logrus.Entry

	peerWatcher *PeerWatcher

	nodeStatesByName map[string]common.NodeState
	nodeNamesByAddr  map[string]string
	nodeStateLock    sync.Mutex
}

func (w *NodeWatcher) isMeshMode() bool {
	if w.DefaultBGPConf.NodeToNodeMeshEnabled != nil {
		return *w.DefaultBGPConf.NodeToNodeMeshEnabled
	}
	return true
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

func (w *NodeWatcher) GetNodeByIp(addr net.IP) *common.NodeState {
	w.nodeStateLock.Lock()
	defer w.nodeStateLock.Unlock()
	nodename, found := w.nodeNamesByAddr[addr.String()]
	if !found {
		return nil
	}
	node, found := w.nodeStatesByName[nodename]
	if !found {
		return nil
	}
	return &node
}

func (w *NodeWatcher) addNodeState(state *common.NodeState) {
	w.nodeStatesByName[state.Name] = *state
	if state.Spec.BGP == nil {
		return
	}
	nodeIP, _, err := net.ParseCIDR(state.Spec.BGP.IPv6Address)
	if err == nil {
		w.nodeNamesByAddr[nodeIP.String()] = state.Name
	}
	nodeIP, _, err = net.ParseCIDR(state.Spec.BGP.IPv4Address)
	if err == nil {
		w.nodeNamesByAddr[nodeIP.String()] = state.Name
	}
}
func (w *NodeWatcher) delNodeState(nodename string) {
	node, found := w.nodeStatesByName[nodename]
	if found && node.Spec.BGP != nil {
		nodeIP, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err == nil {
			delete(w.nodeNamesByAddr, nodeIP.String())
		}
		nodeIP, _, err = net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err == nil {
			delete(w.nodeNamesByAddr, nodeIP.String())
		}
	}
	delete(w.nodeStatesByName, nodename)
}

func (w *NodeWatcher) initialNodeSync() (string, error) {
	w.nodeStateLock.Lock()
	defer w.nodeStateLock.Unlock()
	// TODO: Get and watch only ourselves if there is no mesh
	w.log.Info("Syncing nodes...")
	nodes, err := w.Clientv3.Nodes().List(context.Background(), options.ListOptions{})
	if err != nil {
		return "", errors.Wrap(err, "error listing nodes")
	}
	for _, n := range w.nodeStatesByName {
		n.SweepFlag = true
	}
	for _, calicoNode := range nodes.Items {
		node := nodeSpecCopy(&calicoNode)
		shouldRestart, err := w.handleNodeUpdate(node, watch.Added)
		if err != nil {
			return "", errors.Wrap(err, "error handling node update")
		}
		if shouldRestart {
			return "", fmt.Errorf("Current node configuration changed, restarting")
		}
	}
	for _, node := range w.nodeStatesByName {
		if node.SweepFlag {
			shouldRestart, err := w.handleNodeUpdate(&node, watch.Deleted)
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

func (w *NodeWatcher) WatchNodes(initialResourceVersion string) error {
	var firstWatch = true
	for {
		resourceVersion, err := w.initialNodeSync()
		if err != nil {
			return err
		}
		/* if its the first time in the loop initialResourceVersion happened
		 * before the list in initialNodeSync */
		if firstWatch {
			resourceVersion = initialResourceVersion
			firstWatch = false
		}
		watcher, err := w.Clientv3.Nodes().Watch(
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
				w.log.Infof("nodes watch returned an error")
				break watch
			case watch.Modified, watch.Added:
				calicoNode = update.Object.(*calicov3.Node)
			case watch.Deleted:
				calicoNode = update.Previous.(*calicov3.Node)
			}

			node := nodeSpecCopy(calicoNode)
			w.nodeStateLock.Lock()
			shouldRestart, err := w.handleNodeUpdate(node, update.Type)
			w.nodeStateLock.Unlock()
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
func (w *NodeWatcher) handleNodeUpdate(node *common.NodeState, eventType watch.EventType) (shouldRestart bool, err error) {
	w.log.Debugf("Got node update: %s %s %+v", eventType, node.Name, node)
	if node.Name == config.NodeName {
		old, found := w.nodeStatesByName[node.Name]
		// Always update node state
		w.addNodeState(node)
		// No need to manage ourselves, but if we change we need to restart
		// and reconfigure
		if eventType == watch.Deleted {
			w.log.Infof("node comparison Deleted")
			return true, nil /* restart */
		}
		if found {
			// Check that there were no changes, restart if our BGP config changed
			old.SweepFlag = false
			oldBgp := old.Spec.BGP
			newBgp := node.Spec.BGP
			if oldBgp == nil && newBgp == nil {
				return false, nil /* don't restart */
			} else if oldBgp == nil || newBgp == nil {
				return true, nil /* restart */
			} else if oldBgp.ASNumber != newBgp.ASNumber ||
				oldBgp.IPv4Address != newBgp.IPv4Address ||
				oldBgp.IPv6Address != newBgp.IPv6Address {
				w.log.Infof("BGP Spec changed: old:%+v new:%+v", oldBgp, newBgp)
				return true, nil /* restart */
			}
		}
		return false, nil /* don't restart */
	}

	// If the mesh is disabled, discard all updates that aren't on the current node
	if node.Spec.BGP == nil { // No BGP config for this node
		return false, nil /* don't restart */
	}
	if !w.isMeshMode() {
		return false, nil /* don't restart */
	}
	// This ensures that nodes that don't have a BGP Spec are never present in the state map

	err = nil
	old, found := w.nodeStatesByName[node.Name]
	switch eventType {
	case watch.Error:
		// Shouldn't happen
		return false, fmt.Errorf("Node event error")
	case watch.Added, watch.Modified:
		if found {
			err = w.onNodeUpdated(&old, node)
		} else {
			err = w.onNodeAdded(node)
		}
		w.addNodeState(node)
	case watch.Deleted:
		// This assumes that the old spec and the new spec are identical.
		if found {
			err = w.onNodeDeleted(&old)
			w.delNodeState(node.Name)
		} else {
			return false, fmt.Errorf("Node to delete not found")
		}
	}
	return false, err /* don't restart */
}

func (w *NodeWatcher) getSpecAddresses(node *common.NodeState) (string, string) {
	nodeIP4 := ""
	nodeIP6 := ""
	if node.Spec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv4Address, err)
			nodeIP4 = ""
		} else {
			nodeIP4 = addr.String()
		}
	}
	if node.Spec.BGP.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv6Address, err)
			nodeIP6 = ""
		} else {
			nodeIP6 = addr.String()
		}
	}
	return nodeIP4, nodeIP6
}

func (w *NodeWatcher) OnVppRestart() {
	for _, node := range w.nodeStatesByName {
		w.configureRemoteNodeSnat(&node, true /* isAdd */)
	}
}

func (w *NodeWatcher) configureRemoteNodeSnat(node *common.NodeState, isAdd bool) {
	if node.Spec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv4Address, err)
		} else {
			err = w.Vpp.CnatAddDelSnatPrefix(agentCommon.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				w.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
	if node.Spec.BGP.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv6Address, err)
		} else {
			err = w.Vpp.CnatAddDelSnatPrefix(agentCommon.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				w.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
}

func (w *NodeWatcher) getAsNumber(node *common.NodeState) uint32 {
	if node.Spec.BGP.ASNumber == nil {
		return uint32(*w.DefaultBGPConf.ASNumber)
	} else {
		return uint32(*node.Spec.BGP.ASNumber)
	}
}

func (w *NodeWatcher) onNodeDeleted(old *common.NodeState) error {
	w.configureRemoteNodeSnat(old, false /* isAdd */)
	v4IP, v6IP := w.getSpecAddresses(old)
	if v4IP != "" {
		err := w.peerWatcher.deleteBGPPeer(v4IP)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", v4IP)
		}
	}
	if v6IP != "" {
		err := w.peerWatcher.deleteBGPPeer(v6IP)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", v6IP)
		}
	}
	return nil
}

func (w *NodeWatcher) onNodeUpdatedByAddrFamily(oldAddr string, addr string, oldASN uint32, asNumber uint32) (err error) {
	// Compare IPs and ASN
	switch common.GetStringChangeType(oldAddr, addr) {
	case common.ChangeNone:
		// Address family not configured
	case common.ChangeSame:
		// Check for ASN change
		if oldASN != asNumber {
			// Update peer
			err = w.peerWatcher.updateBGPPeer(addr, asNumber)
			if err != nil {
				return errors.Wrapf(err, "error adding peer %s", addr)
			}
		}
		// Otherwise nothing to do for address family
	case common.ChangeAdded:
		err = w.peerWatcher.addBGPPeer(addr, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", addr)
		}
	case common.ChangeDeleted:
		// Delete old neighbor
		err = w.peerWatcher.deleteBGPPeer(oldAddr)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", oldAddr)
		}
	case common.ChangeUpdated:
		// IP change, delete and re-add neighbor
		err = w.peerWatcher.deleteBGPPeer(oldAddr)
		if err != nil {
			return errors.Wrapf(err, "error deleting peer %s", oldAddr)
		}
		err = w.peerWatcher.addBGPPeer(addr, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", addr)
		}
	}
	return nil
}

func (w *NodeWatcher) onNodeUpdated(old *common.NodeState, node *common.NodeState) (err error) {
	w.log.Debugf("node comparison: old:%+v new:%+v", old.Spec.BGP, node.Spec.BGP)

	newASN := w.getAsNumber(node)
	oldASN := w.getAsNumber(old)
	newV4IP, newV6IP := w.getSpecAddresses(node)
	oldV4IP, oldV6IP := w.getSpecAddresses(old)

	err = w.onNodeUpdatedByAddrFamily(oldV4IP, newV4IP, oldASN, newASN)
	if err != nil {
		return errors.Wrapf(err, "error updating v4")
	}
	err = w.onNodeUpdatedByAddrFamily(oldV6IP, newV6IP, oldASN, newASN)
	if err != nil {
		return errors.Wrapf(err, "error updating v6")
	}

	w.ConnectivityEventChan <- common.ConnectivityEvent{
		Type: common.NodeStateChanged,
		Old:  old,
		New:  node,
	}

	if common.GetStringChangeType(oldV4IP, newV4IP) > common.ChangeSame ||
		common.GetStringChangeType(oldV6IP, newV6IP) > common.ChangeSame {
		w.configureRemoteNodeSnat(old, false /* isAdd */)
		w.configureRemoteNodeSnat(node, true /* isAdd */)
	}

	old.SweepFlag = false
	return nil
}

func (w *NodeWatcher) onNodeAdded(node *common.NodeState) (err error) {
	w.configureRemoteNodeSnat(node, true /* isAdd */)
	asNumber := w.getAsNumber(node)
	v4IP, v6IP := w.getSpecAddresses(node)
	if v4IP != "" {
		err = w.peerWatcher.addBGPPeer(v4IP, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", v4IP)
		}
	}
	if v6IP != "" {
		err = w.peerWatcher.addBGPPeer(v6IP, asNumber)
		if err != nil {
			return errors.Wrapf(err, "error adding peer %s", v6IP)
		}
	}
	return nil
}

func NewNodeWatcher(routingData *common.RoutingData, peerWatcher *PeerWatcher, log *logrus.Entry) *NodeWatcher {
	w := NodeWatcher{
		RoutingData:      routingData,
		log:              log,
		nodeStatesByName: make(map[string]common.NodeState),
		nodeNamesByAddr:  make(map[string]string),
		peerWatcher:      peerWatcher,
	}
	return &w
}
