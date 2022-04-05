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

	nodeStatesByName   map[string]oldv3.Node
	gotOurNodeBGPchan  chan oldv3.NodeBGPSpec
	didWeGetOurNodeBGP bool

	clientv3 calicov3cli.Interface
	vpp      *vpplink.VppLink

	watcher              watch.Interface
	currentWatchRevision string
}

func (w *NodeWatcher) initialNodeSync() (resourceVersion string, err error) {
	// TODO: Get and watch only ourselves if there is no mesh
	w.log.Info("Syncing nodes...")
	nodes, err := w.clientv3.Nodes().List(
		context.Background(),
		options.ListOptions{
			ResourceVersion: w.currentWatchRevision,
		},
	)
	if err != nil {
		return "", errors.Wrap(err, "error listing nodes")
	}
	nodeNames := make(map[string]bool)
	for _, calicoNode := range nodes.Items {
		nodeNames[calicoNode.Name] = true
		err = w.handleNodeUpdate(&calicoNode, true /* isAdd */)
		if err != nil {
			return "", err
		}
	}
	for nodeName, node := range w.nodeStatesByName {
		if _, found := nodeNames[nodeName]; !found {
			err = w.handleNodeUpdate(&node, false /* isAdd */)
			if err != nil {
				return "", err
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
				switch update.Type {
				case watch.Error:
					w.log.Debug("nodes watch returned, restarting")
					goto restart
				case watch.Modified, watch.Added:
					err := w.handleNodeUpdate(update.Object.(*oldv3.Node), true /* isAdd */)
					if err != nil {
						return err
					}
				case watch.Deleted:
					err := w.handleNodeUpdate(update.Previous.(*oldv3.Node), false /* isAdd */)
					if err != nil {
						return err
					}
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

func (w *NodeWatcher) handleNodeUpdate(nodeP *oldv3.Node, isAdd bool) (err error) {
	// This ensures that nodes that don't have a BGP Spec are never present in the state map
	if nodeP == nil || nodeP.Spec.BGP == nil { // No BGP config for this node
		return nil
	}

	node := nodeP.DeepCopy()
	old, found := w.nodeStatesByName[node.Name]
	if isAdd {
		if found {
			err = w.onNodeUpdated(&old, node)
		} else {
			err = w.onNodeAdded(node)
		}
		w.nodeStatesByName[node.Name] = *node
	} else {
		// This assumes that the old spec and the new spec are identical.
		if found {
			err = w.onNodeDeleted(&old)
			delete(w.nodeStatesByName, node.Name)
		} else {
			return fmt.Errorf("Node to delete not found")
		}
	}
	return err
}

func (w *NodeWatcher) configureRemoteNodeSnat(node *oldv3.Node, isAdd bool) {
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

func (w *NodeWatcher) onNodeDeleted(old *oldv3.Node) error {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
	})
	if old.Name == config.NodeName {
		// restart if our BGP config changed
		return NodeWatcherRestartError{}
	}

	w.configureRemoteNodeSnat(old, false /* isAdd */)
	return nil
}

type NodeWatcherRestartError struct{}

func (e NodeWatcherRestartError) Error() string {
	return "node configuration changed, restarting"
}

func (w *NodeWatcher) onNodeUpdated(old *oldv3.Node, node *oldv3.Node) (err error) {
	w.log.Debugf("node comparison: old:%+v new:%+v", old.Spec.BGP, node.Spec.BGP)

	newV4IP, newV6IP := common.GetNodeSpecAddresses(node)
	oldV4IP, oldV6IP := common.GetNodeSpecAddresses(old)

	// This is used by the routing server to process Wireguard key updates
	// As a result we only send an event when a node is updated, not when it is added or deleted
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
		New:  node,
	})

	change := common.GetStringChangeType(oldV4IP, newV4IP) | common.GetStringChangeType(oldV6IP, newV6IP)
	if change&(common.ChangeDeleted|common.ChangeUpdated) != 0 && node.Name == config.NodeName {
		// restart if our BGP config changed
		return NodeWatcherRestartError{}
	}
	if change != common.ChangeSame {
		w.configureRemoteNodeSnat(old, false /* isAdd */)
		w.configureRemoteNodeSnat(node, true /* isAdd */)
	}

	return nil
}

func (w *NodeWatcher) onNodeAdded(node *oldv3.Node) (err error) {
	if node.Name == config.NodeName && !w.didWeGetOurNodeBGP {
		nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(node.Spec.BGP)
		if nodeIP4 != nil || nodeIP6 != nil {
			/* We found a BGP Spec that seems valid enough */
			w.gotOurNodeBGPchan <- *node.Spec.BGP
			w.didWeGetOurNodeBGP = true
		}
	}

	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		New:  node,
	})
	w.configureRemoteNodeSnat(node, true /* isAdd */)

	return nil
}

func NewNodeWatcher(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, log *logrus.Entry) *NodeWatcher {
	w := NodeWatcher{
		vpp:                vpp,
		log:                log,
		clientv3:           clientv3,
		nodeStatesByName:   make(map[string]oldv3.Node),
		gotOurNodeBGPchan:  make(chan oldv3.NodeBGPSpec, 10),
		didWeGetOurNodeBGP: false,
	}

	return &w
}
