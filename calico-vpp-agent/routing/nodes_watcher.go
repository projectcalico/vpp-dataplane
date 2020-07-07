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

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
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
) (bool, error) {
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

	var v4IP, v6IP net.IP
	var asNumber uint32
	var err error
	if newSpec.BGP.ASNumber == nil {
		asNumber = uint32(*s.defaultBGPConf.ASNumber)
	} else {
		asNumber = uint32(*newSpec.BGP.ASNumber)
	}
	v4Set := newSpec.BGP.IPv4Address != ""
	if v4Set {
		v4IP, _, err = net.ParseCIDR(newSpec.BGP.IPv4Address)
		if err != nil {
			return false, errors.Wrapf(err, "cannot parse node v4: %s", newSpec.BGP.IPv4Address)
		}
	}
	v6Set := newSpec.BGP.IPv6Address != ""
	if v6Set {
		v6IP, _, err = net.ParseCIDR(newSpec.BGP.IPv6Address)
		if err != nil {
			return false, errors.Wrapf(err, "cannot parse node v6: %s", newSpec.BGP.IPv6Address)
		}
	}
	switch eventType {
	case watch.Error: // Shouldn't happen
	case watch.Added, watch.Modified:
		old, found := state[nodeName]
		if found {
			s.log.Debugf("node comparison: old:%+v new:%+v", old.Spec.BGP, newSpec.BGP)
			var oldASN uint32
			if old.Spec.BGP.ASNumber != nil {
				oldASN = uint32(*old.Spec.BGP.ASNumber)
			} else {
				oldASN = uint32(*s.defaultBGPConf.ASNumber)
			}
			oldV4Set := old.Spec.BGP.IPv4Address != ""
			oldV6Set := old.Spec.BGP.IPv6Address != ""
			var oldV4IP, oldV6IP net.IP
			if oldV4Set { // These shouldn't error since they have already been parsed successfully
				oldV4IP, _, _ = net.ParseCIDR(old.Spec.BGP.IPv4Address)
			}
			if oldV6Set {
				oldV6IP, _, _ = net.ParseCIDR(old.Spec.BGP.IPv6Address)
			}

			// Compare IPs and ASN
			if v4Set {
				if oldV4Set {
					if old.Spec.BGP.IPv4Address != newSpec.BGP.IPv4Address {
						// IP change, delete and re-add neighbor
						err = s.deleteBGPPeer(oldV4IP.String())
						if err != nil {
							return false, errors.Wrapf(err, "error deleting peer %s", oldV4IP.String())
						}
						err = s.addBGPPeer(v4IP.String(), asNumber)
						if err != nil {
							return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
						}
					} else {
						// Check for ASN change
						if oldASN != asNumber {
							// Update peer
							err = s.updateBGPPeer(v4IP.String(), asNumber)
							if err != nil {
								return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
							}
						} // Otherwise nothing to do for v4
					}
				} else {
					err = s.addBGPPeer(v4IP.String(), asNumber)
					if err != nil {
						return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
					}
				}
			} else {
				// No v4 address on new node
				if oldV4Set {
					// Delete old neighbor
					err = s.deleteBGPPeer(oldV4IP.String())
					if err != nil {
						return false, errors.Wrapf(err, "error deleting peer %s", oldV4IP.String())
					}
				} // Else nothing to do for v6
			}
			if v6Set {
				if oldV6Set {
					if old.Spec.BGP.IPv6Address != newSpec.BGP.IPv6Address {
						// IP change, delete and re-add neighbor
						err = s.deleteBGPPeer(oldV6IP.String())
						if err != nil {
							return false, errors.Wrapf(err, "error deleting peer %s", oldV6IP.String())
						}
						err = s.addBGPPeer(v6IP.String(), asNumber)
						if err != nil {
							return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
						}
					} else {
						// Check for ASN change
						if oldASN != asNumber {
							// Update peer
							err = s.updateBGPPeer(v6IP.String(), asNumber)
							if err != nil {
								return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
							}
						} // Otherwise nothing to do for v6
					}
				} else {
					err = s.addBGPPeer(v6IP.String(), asNumber)
					if err != nil {
						return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
					}
				}
			} else {
				// No v6 address on new node
				if oldV6Set {
					// Delete old neighbor
					err = s.deleteBGPPeer(oldV6IP.String())
					if err != nil {
						return false, errors.Wrapf(err, "error deleting peer %s", oldV6IP.String())
					}
				} // Else nothing to do for v6
			}
			old.SweepFlag = false
			old.Spec = newSpec
		} else {
			// New node
			state[nodeName] = &node{
				Spec:      newSpec,
				SweepFlag: false,
			}
			if v4Set {
				err = s.addBGPPeer(v4IP.String(), asNumber)
				if err != nil {
					return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
				}
			}
			if v6Set {
				err = s.addBGPPeer(v6IP.String(), asNumber)
				if err != nil {
					return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
				}
			}
		}
	case watch.Deleted:
		_, found := state[nodeName]
		// This assumes that the old spec and the new spec are identical.
		if found {
			if v4Set {
				err = s.deleteBGPPeer(v4IP.String())
				if err != nil {
					return false, errors.Wrapf(err, "error deleting peer %s", v4IP.String())
				}
			}
			if v6Set {
				err = s.deleteBGPPeer(v6IP.String())
				if err != nil {
					return false, errors.Wrapf(err, "error deleting peer %s", v6IP.String())
				}
			}
			delete(state, nodeName)
		} else {
			return false, fmt.Errorf("Node to delete not found")
		}

	}
	return false, nil
}
