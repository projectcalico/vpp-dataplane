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

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type NodeWatcherRestartError struct{}

func (e NodeWatcherRestartError) Error() string {
	return "node configuration changed, restarting"
}

func (s *PoliciesHandler) OnHostMetadataV4V6Update(msg *proto.HostMetadataV4V6Update) (err error) {
	localNodeSpec, err := common.NewLocalNodeSpec(msg)
	if err != nil {
		return errors.Wrapf(err, "OnHostMetadataV4V6Update errored")
	}
	old, found := s.cache.NodeStatesByName[localNodeSpec.Name]

	if localNodeSpec.Name == *config.NodeName &&
		(localNodeSpec.IPv4Address != nil || localNodeSpec.IPv6Address != nil) {
		/* We found a BGP Spec that seems valid enough */
		s.GotOurNodeBGPchanOnce.Do(func() {
			s.GotOurNodeBGPchan <- localNodeSpec
		})
		err = s.createAllowFromHostPolicy()
		if err != nil {
			return errors.Wrap(err, "Error in creating AllowFromHostPolicy")
		}
		err = s.createAllowToHostPolicy()
		if err != nil {
			return errors.Wrap(err, "Error in createAllowToHostPolicy")
		}
	}

	// This is used by the routing server to process Wireguard key updates
	// As a result we only send an event when a node is updated, not when it is added or deleted
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
		New:  localNodeSpec,
	})

	if !found {
		s.configureRemoteNodeSnat(localNodeSpec, true /* isAdd */)
	} else {
		change := common.GetIPNetChangeType(old.IPv4Address, localNodeSpec.IPv4Address) | common.GetIPNetChangeType(old.IPv6Address, localNodeSpec.IPv6Address)
		if change&(common.ChangeDeleted|common.ChangeUpdated) != 0 && localNodeSpec.Name == *config.NodeName {
			// restart if our BGP config changed
			return NodeWatcherRestartError{}
		}
		if change != common.ChangeSame {
			s.configureRemoteNodeSnat(old, false /* isAdd */)
			s.configureRemoteNodeSnat(localNodeSpec, true /* isAdd */)
		}
	}

	if old != nil {
		if old.IPv4Address != nil {
			delete(s.cache.NodeByAddr, old.IPv4Address.IP.String())
		}
		if old.IPv6Address != nil {
			delete(s.cache.NodeByAddr, old.IPv6Address.IP.String())
		}
	}
	s.cache.NodeStatesByName[localNodeSpec.Name] = localNodeSpec
	if localNodeSpec.IPv4Address != nil {
		s.cache.NodeByAddr[localNodeSpec.IPv4Address.IP.String()] = localNodeSpec
	}
	if localNodeSpec.IPv6Address != nil {
		s.cache.NodeByAddr[localNodeSpec.IPv6Address.IP.String()] = localNodeSpec
	}
	return nil
}

func (s *PoliciesHandler) OnHostMetadataV4V6Remove(msg *proto.HostMetadataV4V6Remove) (err error) {
	old, found := s.cache.NodeStatesByName[msg.Hostname]
	if !found {
		return fmt.Errorf("node %s to delete not found", msg.Hostname)
	}

	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
	})
	if old.Name == *config.NodeName {
		// restart if our BGP config changed
		return NodeWatcherRestartError{}
	}
	s.configureRemoteNodeSnat(old, false /* isAdd */)
	delete(s.cache.NodeStatesByName, msg.Hostname)
	if old.IPv4Address != nil {
		delete(s.cache.NodeByAddr, old.IPv4Address.IP.String())
	}
	if old.IPv6Address != nil {
		delete(s.cache.NodeByAddr, old.IPv6Address.IP.String())
	}
	return nil
}

func (s *PoliciesHandler) configureRemoteNodeSnat(node *common.LocalNodeSpec, isAdd bool) {
	if node.IPv4Address != nil {
		err := s.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(node.IPv4Address.IP), isAdd)
		if err != nil {
			s.log.Errorf("error configuring snat prefix for current node (%v): %v", node.IPv4Address.IP, err)
		}
	}
	if node.IPv6Address != nil {
		err := s.vpp.CnatAddDelSnatPrefix(common.ToMaxLenCIDR(node.IPv6Address.IP), isAdd)
		if err != nil {
			s.log.Errorf("error configuring snat prefix for current node (%v): %v", node.IPv6Address.IP, err)
		}
	}
}
