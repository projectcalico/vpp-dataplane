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
	"strings"
	"time"

	"github.com/pkg/errors"
	//oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

type NodeWatcher struct {
	log *logrus.Entry

	nodeStatesByName   map[string]common.LocalNodeSpec
	gotOurNodeBGPchan  chan common.LocalNodeSpec
	didWeGetOurNodeBGP bool

	clientv3 calicov3cli.Interface
	vpp      *vpplink.VppLink

	currentWatchRevision string
	nodeEventChan        chan common.CalicoVppEvent
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
		err = w.handleNodeUpdate(
			&common.LocalNodeSpec{
				ASNumber:           calicoNode.Spec.BGP.ASNumber,
				Name:               calicoNode.Name,
				IPv4Address:        calicoNode.Spec.BGP.IPv4Address,
				IPv6Address:        calicoNode.Spec.BGP.IPv6Address,
				Labels:             calicoNode.Labels,
				WireguardPublicKey: calicoNode.Status.WireguardPublicKey,
			}, true /* isAdd */)
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
		err := w.resync()
		if err != nil {
			w.log.Error(err)
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				w.log.Infof("Nodes Watcher asked to stop")
				return nil
			case event := <-w.nodeEventChan:
				switch event.Type {
				case common.NodeRouteUpdate:
					node := event.New.(*proto.RouteUpdate)
					localNodeSpec := &common.LocalNodeSpec{
						Name:               node.DstNodeName,
						Labels:             node.Labels,
						WireguardPublicKey: node.WireguardPublicKey,
					}
					if node.Asnumber != "" {
						asn, err := numorstring.ASNumberFromString(node.Asnumber)
						if err != nil {
							return err
						}
						localNodeSpec.ASNumber = &asn
					}
					if strings.Contains(node.Dst, ":") {
						localNodeSpec.IPv6Address = node.Dst
					} else {
						localNodeSpec.IPv4Address = node.Dst
					}
					err = w.handleNodeUpdate(localNodeSpec, true /* isAdd */)
					if err != nil {
						return err
					}
				case common.NodeRouteDelete:
					node := event.Old.(*common.NodeRouteRemove)
					localNodeSpec := &common.LocalNodeSpec{Name: node.Name}
					if strings.Contains(node.Dst, ":") {
						localNodeSpec.IPv6Address = node.Dst
					} else {
						localNodeSpec.IPv4Address = node.Dst
					}
					err := w.handleNodeUpdate(localNodeSpec, false /* isAdd */)
					if err != nil {
						return err
					}
				}
			}
		}

	restart:
		w.log.Debug("restarting nodes watcher...")
		time.Sleep(2 * time.Second)
	}
	return nil
}

func (w *NodeWatcher) resync() error {
	if w.currentWatchRevision == "" {
		resourceVersion, err := w.initialNodeSync()
		if err != nil {
			return err
		}
		w.currentWatchRevision = resourceVersion
	}
	return nil
}

func (w *NodeWatcher) WaitForOurBGPSpec() *common.LocalNodeSpec {
	bgpspec := <-w.gotOurNodeBGPchan
	return &bgpspec
}

func (w *NodeWatcher) handleNodeUpdate(node *common.LocalNodeSpec, isAdd bool) (err error) {
	// This ensures that nodes that don't have a BGP Spec are never present in the state map
	if node == nil { // No BGP config for this node
		return nil
	}

	old, found := w.nodeStatesByName[node.Name]
	if isAdd {
		if found {
			err = w.onNodeUpdated(&old, node)
		} else {
			err = w.onNodeAdded(node)
		}
		w.nodeStatesByName[node.Name] = *node
	} else {
		if found {
			err = w.onNodeDeleted(&old, node)
			if old.IPv4Address == "" && old.IPv6Address == "" { //both addresses deleted
				w.log.Infof("deleted node %+v", node)
				delete(w.nodeStatesByName, node.Name)
			}
		} else {
			return fmt.Errorf("Node to delete not found")
		}
	}
	return err
}

func (w *NodeWatcher) configureRemoteNodeSnat(node *common.LocalNodeSpec, isAdd bool) {
	if node.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.IPv4Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.IPv4Address, err)
		} else {
			err = w.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				w.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
	if node.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(node.IPv6Address)
		if err != nil {
			w.log.Errorf("cannot parse node address %s: %v", node.IPv6Address, err)
		} else {
			err = w.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(addr), isAdd)
			if err != nil {
				w.log.Errorf("error configuring snat prefix for current node (%v): %v", addr, err)
			}
		}
	}
}

func (w *NodeWatcher) onNodeDeleted(old *common.LocalNodeSpec, node *common.LocalNodeSpec) error {
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
	})
	if old.Name == config.NodeName {
		// restart if our BGP config changed
		return NodeWatcherRestartError{}
	}

	if node.IPv4Address != "" {
		old.IPv4Address = ""
	}
	if node.IPv6Address != "" {
		old.IPv6Address = ""
	}
	w.configureRemoteNodeSnat(old, false /* isAdd */)
	return nil
}

type NodeWatcherRestartError struct{}

func (e NodeWatcherRestartError) Error() string {
	return "node configuration changed, restarting"
}

func (w *NodeWatcher) onNodeUpdated(old *common.LocalNodeSpec, node *common.LocalNodeSpec) (err error) {
	//w.log.Infof("node comparison: old:%+v new:%+v", old, node)

	newV4IP, newV6IP := node.IPv4Address, node.IPv6Address
	oldV4IP, oldV6IP := old.IPv4Address, old.IPv6Address
	if node.IPv4Address == "" {
		node.IPv4Address = old.IPv4Address
	}
	if node.IPv6Address == "" {
		node.IPv6Address = old.IPv6Address
	}

	// This is used by the routing server to process Wireguard key updates
	// As a result we only send an event when a node is updated, not when it is added or deleted
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
		New:  node,
	})

	// RouteUpdates contain either ipv4 or ipv6 address, so restart is needed when both change not just one
	change := common.GetStringChangeType(oldV4IP, newV4IP) & common.GetStringChangeType(oldV6IP, newV6IP)
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

func (w *NodeWatcher) onNodeAdded(node *common.LocalNodeSpec) (err error) {
	if node.Name == config.NodeName && !w.didWeGetOurNodeBGP {
		nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(node)
		if nodeIP4 != nil || nodeIP6 != nil {
			/* We found a BGP Spec that seems valid enough */
			w.gotOurNodeBGPchan <- *node
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
		nodeStatesByName:   make(map[string]common.LocalNodeSpec),
		gotOurNodeBGPchan:  make(chan common.LocalNodeSpec, 10),
		didWeGetOurNodeBGP: false,
		nodeEventChan:      make(chan common.CalicoVppEvent),
	}
	reg := common.RegisterHandler(w.nodeEventChan, "node watcher events")
	reg.ExpectEvents(common.NodeRouteUpdate, common.NodeRouteDelete)
	return &w
}
