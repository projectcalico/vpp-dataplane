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
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

var (
	state = make(map[string]*node)
)

type node struct {
	Spec      *calicov3.NodeSpec
	SweepFlag bool
}

func (s *Server) isMeshMode() bool {
	return *s.defaultBGPConf.NodeToNodeMeshEnabled
}

func nodeSpecCopy(s *calicov3.NodeSpec) *calicov3.NodeSpec {
	r := &calicov3.NodeSpec{
		IPv4VXLANTunnelAddr: s.IPv4VXLANTunnelAddr,
		VXLANTunnelMACAddr:  s.VXLANTunnelMACAddr,
		OrchRefs:            append([]calicov3.OrchRef{}, s.OrchRefs...),
	}
	if s.BGP != nil {
		r.BGP = &calicov3.NodeBGPSpec{
			IPv4Address:             s.BGP.IPv4Address,
			IPv6Address:             s.BGP.IPv6Address,
			IPv4IPIPTunnelAddr:      s.BGP.IPv4IPIPTunnelAddr,
			RouteReflectorClusterID: s.BGP.RouteReflectorClusterID,
		}
		if s.BGP.ASNumber != nil {
			r.BGP.ASNumber = new(numorstring.ASNumber)
			*r.BGP.ASNumber = *s.BGP.ASNumber
		}
	}
	return r
}

func (s *Server) GetNodeByIp(addr net.IP) *calicov3.NodeSpec {
	for _, node := range state {
		if vpplink.IsIP6(addr) {
			nodeIP, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
			if err == nil {
				if addr.Equal(nodeIP) {
					return node.Spec
				}
			}
		} else {
			nodeIP, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
			if err == nil {
				if addr.Equal(nodeIP) {
					return node.Spec
				}
			}
		}
	}
	return nil
}

func (s *Server) watchNodes(initialResourceVersion string) error {
	isMesh := s.isMeshMode()
	var firstWatch = true
	for {
		// TODO: Get and watch only ourselves if there is no mesh
		s.log.Info("Syncing nodes...")
		nodes, err := s.clientv3.Nodes().List(context.Background(), options.ListOptions{})
		if err != nil {
			return errors.Wrap(err, "error listing nodes")
		}
		for _, n := range state {
			n.SweepFlag = true
		}
		for _, node := range nodes.Items {
			spec := nodeSpecCopy(&node.Spec)
			shouldRestart, err := s.handleNodeUpdate(state, node.Name, spec, watch.Added, isMesh)
			if err != nil {
				return errors.Wrap(err, "error handling node update")
			}
			if shouldRestart {
				return fmt.Errorf("Current node configuration changed, restarting")
			}
		}
		for name, node := range state {
			if node.SweepFlag {
				shouldRestart, err := s.handleNodeUpdate(state, name, node.Spec, watch.Deleted, isMesh)
				if err != nil {
					return errors.Wrap(err, "error handling node update")
				}
				if shouldRestart {
					return fmt.Errorf("Current node configuration changed, restarting")
				}
			}
		}

		var resourceVersion string
		if firstWatch {
			resourceVersion = initialResourceVersion
			firstWatch = false
		} else {
			resourceVersion = nodes.ResourceVersion
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
			var node *calicov3.Node
			switch update.Type {
			case watch.Error:
				switch update.Error.(type) {
				case calicoerr.ErrorWatchTerminated:
					break watch
				default:
					return errors.Wrap(update.Error, "error while watching for Node updates")
				}
			case watch.Modified, watch.Added:
				node = update.Object.(*calicov3.Node)
			case watch.Deleted:
				node = update.Previous.(*calicov3.Node)
			}

			spec := nodeSpecCopy(&node.Spec)
			shouldRestart, err := s.handleNodeUpdate(state, node.Name, spec, update.Type, isMesh)
			if err != nil {
				return errors.Wrap(err, "error handling node update")
			}
			if shouldRestart {
				return fmt.Errorf("Current node configuration changed, restarting")
			}
		}
	}
	return nil
}

// Returns true if the config of the current node has changed and requires a restart
// Sets node.SweepFlag to false if an existing node is added to allow mark and sweep
func (s *Server) handleNodeUpdate(
	state map[string]*node,
	nodeName string,
	newSpec *calicov3.NodeSpec,
	eventType watch.EventType,
	isMesh bool,
) (shouldRestart bool, err error) {
	s.log.Debugf("Got node update: mesh:%t %s %s %+v %v", isMesh, eventType, nodeName, newSpec, state)
	if nodeName == config.NodeName {
		// No need to manage ourselves, but if we change we need to restart and reconfigure
		if eventType == watch.Deleted {
			return true, nil
		} else {
			old, found := state[nodeName]
			if found {
				// Check that there were no changes, restart if our BGP config changed
				old.SweepFlag = false
				s.log.Tracef("node comparison: old:%+v new:%+v", old.Spec.BGP, newSpec.BGP)
				return !reflect.DeepEqual(old.Spec.BGP, newSpec.BGP), nil
			} else {
				// First pass, create local node
				state[nodeName] = &node{
					Spec:      newSpec,
					SweepFlag: false,
				}
				return false, nil
			}
		}
	}

	// If the mesh is disabled, discard all updates that aren't on the current node
	if !isMesh || newSpec.BGP == nil { // No BGP config for this node
		return false, nil
	}
	// This ensures that nodes that don't have a BGP Spec are never present in the state map

	err = nil
	switch eventType {
	case watch.Error: // Shouldn't happen
	case watch.Added, watch.Modified:
		old, found := state[nodeName]
		if found {
			err = s.onNodeUpdated(old, newSpec)
		} else {
			// New node
			state[nodeName] = &node{
				Spec:      newSpec,
				SweepFlag: false,
			}
			err = s.onNodeAdded(newSpec)
		}
	case watch.Deleted:
		old, found := state[nodeName]
		// This assumes that the old spec and the new spec are identical.
		if found {
			err = s.onNodeDeleted(old)
			delete(state, nodeName)
		} else {
			return false, fmt.Errorf("Node to delete not found")
		}

	}
	return false, err
}

func (s *Server) getSpecAddresses(newSpec *calicov3.NodeSpec) (string, string) {
	nodeIP4 := ""
	nodeIP6 := ""
	if newSpec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(newSpec.BGP.IPv4Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", newSpec.BGP.IPv4Address, err)
			nodeIP4 = ""
		} else {
			nodeIP4 = addr.String()
		}
	}
	if nodeIP6 != "" {
		addr, _, err := net.ParseCIDR(newSpec.BGP.IPv6Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", newSpec.BGP.IPv6Address, err)
			nodeIP6 = ""
		} else {
			nodeIP6 = addr.String()
		}
	}
	return nodeIP4, nodeIP6
}


func (s *Server) getAsNumber(newSpec *calicov3.NodeSpec) uint32 {
	if newSpec.BGP.ASNumber == nil {
		return uint32(*s.defaultBGPConf.ASNumber)
	} else {
		return uint32(*newSpec.BGP.ASNumber)
	}
}

func (s *Server) onNodeDeleted(old *node) error {
	v4IP, v6IP := s.getSpecAddresses(old.Spec)
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

func (s *Server) onNodeUpdated(old *node, newSpec *calicov3.NodeSpec) (err error) {
	s.log.Debugf("node comparison: old:%+v new:%+v", old.Spec.BGP, newSpec.BGP)

	asNumber := s.getAsNumber(newSpec)
	oldASN := s.getAsNumber(old.Spec)
	v4IP, v6IP := s.getSpecAddresses(newSpec)
	oldV4IP, oldV6IP := s.getSpecAddresses(old.Spec)

	// Compare IPs and ASN
	if v4IP != "" {
		if oldV4IP != "" {
			if old.Spec.BGP.IPv4Address != newSpec.BGP.IPv4Address {
				// IP change, delete and re-add neighbor
				err = s.deleteBGPPeer(oldV4IP)
				if err != nil {
					return errors.Wrapf(err, "error deleting peer %s", oldV4IP)
				}
				err = s.addBGPPeer(v4IP, asNumber)
				if err != nil {
					return errors.Wrapf(err, "error adding peer %s", v4IP)
				}
			} else {
				// Check for ASN change
				if oldASN != asNumber {
					// Update peer
					err = s.updateBGPPeer(v4IP, asNumber)
					if err != nil {
						return errors.Wrapf(err, "error adding peer %s", v4IP)
					}
				} // Otherwise nothing to do for v4
			}
		} else {
			err = s.addBGPPeer(v4IP, asNumber)
			if err != nil {
				return errors.Wrapf(err, "error adding peer %s", v4IP)
			}
		}
	} else {
		// No v4 address on new node
		if oldV4IP != "" {
			// Delete old neighbor
			err = s.deleteBGPPeer(oldV4IP)
			if err != nil {
				return errors.Wrapf(err, "error deleting peer %s", oldV4IP)
			}
		} // Else nothing to do for v6
	}
	if v6IP != "" {
		if oldV6IP != "" {
			if old.Spec.BGP.IPv6Address != newSpec.BGP.IPv6Address {
				// IP change, delete and re-add neighbor
				err = s.deleteBGPPeer(oldV6IP)
				if err != nil {
					return errors.Wrapf(err, "error deleting peer %s", oldV6IP)
				}
				err = s.addBGPPeer(v6IP, asNumber)
				if err != nil {
					return errors.Wrapf(err, "error adding peer %s", v6IP)
				}
			} else {
				// Check for ASN change
				if oldASN != asNumber {
					// Update peer
					err = s.updateBGPPeer(v6IP, asNumber)
					if err != nil {
						return errors.Wrapf(err, "error adding peer %s", v6IP)
					}
				} // Otherwise nothing to do for v6
			}
		} else {
			err = s.addBGPPeer(v6IP, asNumber)
			if err != nil {
				return errors.Wrapf(err, "error adding peer %s", v6IP)
			}
		}
	} else {
		// No v6 address on new node
		if oldV6IP != "" {
			// Delete old neighbor
			err = s.deleteBGPPeer(oldV6IP)
			if err != nil {
				return errors.Wrapf(err, "error deleting peer %s", oldV6IP)
			}
		} // Else nothing to do for v6
	}
	old.SweepFlag = false
	old.Spec = newSpec
	return nil
}

func (s *Server) onNodeAdded(newSpec *calicov3.NodeSpec) (err error) {
	asNumber := s.getAsNumber(newSpec)
	v4IP, v6IP := s.getSpecAddresses(newSpec)
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

