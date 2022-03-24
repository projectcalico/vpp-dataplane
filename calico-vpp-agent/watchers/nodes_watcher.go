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
	"time"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

type NodeWatcher struct {
	log *logrus.Entry

	nodeStatesByName   map[string]common.NodeState
	gotOurNodeBGPchan  chan oldv3.NodeBGPSpec
	didWeGetOurNodeBGP bool

	clientv3 calicov3cli.Interface
	vpp      *vpplink.VppLink

	watcher              watch.Interface
	currentWatchRevision string
}

func nodeSpecCopy(calicoNode *calicov3.Node) *common.NodeState {
	return &common.NodeState{
		Node:      *calicoNode.DeepCopy(),
		SweepFlag: false,
	}
}

func (w *NodeWatcher) initialNodeSync() (string, error) {
	// TODO: Get and watch only ourselves if there is no mesh
	w.log.Info("Syncing nodes...")
	nodes, err := w.clientv3.Nodes().List(context.Background(), options.ListOptions{
		ResourceVersion: w.currentWatchRevision,
	})
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

func (w *NodeWatcher) WatchNodes(t *tomb.Tomb) error {
	for t.Alive() {
		w.currentWatchRevision = ""
		err := w.resyncAndCreateWatcher()
		if err != nil {
			w.log.Error(err)
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				w.log.Infof("Nodes Watcher asked to stop")
				w.cleanExistingWatcher()
				return nil
			case update, ok := <-w.watcher.ResultChan():
				if !ok {
					w.log.Debug("nodes watch channel closed, restarting...")
					err := w.resyncAndCreateWatcher()
					if err != nil {
						goto restart
					}
					continue
				}
				var calicoNode *calicov3.Node
				switch update.Type {
				case watch.Error:
					w.log.Debug("nodes watch returned, restarting")
					goto restart
				case watch.Modified, watch.Added:
					calicoNode = update.Object.(*calicov3.Node)
				case watch.Deleted:
					calicoNode = update.Previous.(*calicov3.Node)
				}

				node := nodeSpecCopy(calicoNode)
				shouldRestart, err := w.handleNodeUpdate(node, update.Type)
				if err != nil {
					return errors.Wrap(err, "error handling node update")
				}
				if shouldRestart {
					return fmt.Errorf("Current node configuration changed, restarting")
				}
			}
		}

	restart:
		w.log.Debug("restarting nodes watcher...")
		w.cleanExistingWatcher()
		time.Sleep(2 * time.Second)
	}
	return nil
}

func (w *NodeWatcher) resyncAndCreateWatcher() error {
	if w.currentWatchRevision == "" {
		resourceVersion, err := w.initialNodeSync()
		if err != nil {
			return err
		}
		w.currentWatchRevision = resourceVersion
	}
	w.cleanExistingWatcher()
	watcher, err := w.clientv3.Nodes().Watch(
		context.Background(),
		options.ListOptions{ResourceVersion: w.currentWatchRevision},
	)
	if err != nil {
		return err
	}
	w.watcher = watcher
	return nil
}

func (w *NodeWatcher) cleanExistingWatcher() {
	if w.watcher != nil {
		w.watcher.Stop()
		w.log.Debug("Stopped watcher")
		w.watcher = nil
	}
}

func (w *NodeWatcher) WaitForOurBGPSpec() *oldv3.NodeBGPSpec {
	bgpspec := <-w.gotOurNodeBGPchan
	return &bgpspec
}

// Returns true if the config of the current node has changed and requires a restart
// Sets node.SweepFlag to false if an existing node is added to allow mark and sweep
func (w *NodeWatcher) handleNodeUpdate(node *common.NodeState, eventType watch.EventType) (shouldRestart bool, err error) {
	w.log.Debugf("Got node update: %s %s %+v", eventType, node.Name, node)
	if node.Name == config.NodeName {
		old, found := w.nodeStatesByName[node.Name]
		// Always update node state
		w.nodeStatesByName[node.Name] = *node
		// No need to manage ourselves, but if we change we need to restart
		// and reconfigure
		if eventType == watch.Deleted {
			w.log.Infof("node comparison Deleted")
			return true, nil /* restart */
		}
		if node.Spec.BGP != nil && !w.didWeGetOurNodeBGP {
			nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(node.Spec.BGP)
			if nodeIP4 != nil || nodeIP6 != nil {
				/* We found a BGP Spec that seems valid enough */
				w.gotOurNodeBGPchan <- *node.Spec.BGP
				w.didWeGetOurNodeBGP = true
			}
		}
		common.SendEvent(common.CalicoVppEvent{
			Type: common.OurNodeStateChanged,
			Old:  &old.Node,
			New:  &node.Node,
		})
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

	// This ensures that nodes that don't have a BGP Spec are never present in the state map
	if node.Spec.BGP == nil { // No BGP config for this node
		return false, nil /* don't restart */
	}

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
		w.nodeStatesByName[node.Name] = *node
	case watch.Deleted:
		// This assumes that the old spec and the new spec are identical.
		if found {
			err = w.onNodeDeleted(&old)
			delete(w.nodeStatesByName, node.Name)
		} else {
			return false, fmt.Errorf("Node to delete not found")
		}
	}
	return false, err /* don't restart */
}

func (w *NodeWatcher) configureRemoteNodeSnat(node *common.NodeState, isAdd bool) {
	if node.Spec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.Spec.BGP.IPv4Address, err)
		} else {
			err = w.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(addr), isAdd)
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
			err = w.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				w.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
}

func (w *NodeWatcher) onNodeDeleted(old *common.NodeState) error {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  &old.Node,
	})
	w.configureRemoteNodeSnat(old, false /* isAdd */)
	return nil
}

func (w *NodeWatcher) onNodeUpdated(old *common.NodeState, node *common.NodeState) (err error) {
	w.log.Debugf("node comparison: old:%+v new:%+v", old.Spec.BGP, node.Spec.BGP)

	newV4IP, newV6IP := common.GetNodeSpecAddresses(&node.Node)
	oldV4IP, oldV6IP := common.GetNodeSpecAddresses(&old.Node)

	// This is used by the routing server to process Wireguard key updates
	// As a result we only send an event when a node is updated, not when it is added or deleted
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  &old.Node,
		New:  &node.Node,
	})

	if common.GetStringChangeType(oldV4IP, newV4IP) > common.ChangeSame ||
		common.GetStringChangeType(oldV6IP, newV6IP) > common.ChangeSame {
		w.configureRemoteNodeSnat(old, false /* isAdd */)
		w.configureRemoteNodeSnat(node, true /* isAdd */)
	}

	old.SweepFlag = false
	return nil
}

func (w *NodeWatcher) onNodeAdded(node *common.NodeState) (err error) {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		New:  &node.Node,
	})
	w.configureRemoteNodeSnat(node, true /* isAdd */)
	return nil
}

func NewNodeWatcher(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, log *logrus.Entry) *NodeWatcher {
	w := NodeWatcher{
		vpp:               vpp,
		log:               log,
		clientv3:          clientv3,
		gotOurNodeBGPchan: make(chan oldv3.NodeBGPSpec, 10),
		nodeStatesByName:  make(map[string]common.NodeState),
	}
	return &w
}
