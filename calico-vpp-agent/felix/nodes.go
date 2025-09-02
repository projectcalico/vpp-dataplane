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

package felix

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

func (s *Server) handleHostMetadataV4V6Update(msg *proto.HostMetadataV4V6Update) (err error) {
	var ip4net, ip6net *net.IPNet
	var ip4, ip6 net.IP
	if msg.Ipv4Addr != "" {
		ip4, ip4net, err = net.ParseCIDR(msg.Ipv4Addr)
		if err != nil {
			return err
		}
		ip4net.IP = ip4
	}
	if msg.Ipv6Addr != "" {
		ip6, ip6net, err = net.ParseCIDR(msg.Ipv6Addr)
		if err != nil {
			return err
		}
		ip6net.IP = ip6
	}

	localNodeSpec := &common.LocalNodeSpec{
		Name:        msg.Hostname,
		Labels:      msg.Labels,
		IPv4Address: ip4net,
		IPv6Address: ip6net,
	}
	if msg.Asnumber != "" {
		asn, err := numorstring.ASNumberFromString(msg.Asnumber)
		if err != nil {
			return err
		}
		localNodeSpec.ASNumber = &asn
	}

	old, found := s.cache.NodeStatesByName[localNodeSpec.Name]
	if found {
		err = s.onNodeUpdated(old, localNodeSpec)
	} else {
		err = s.onNodeAdded(localNodeSpec)
	}
	s.cache.NodeStatesByName[localNodeSpec.Name] = localNodeSpec
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) handleHostMetadataV4V6Remove(msg *proto.HostMetadataV4V6Remove) (err error) {
	localNodeSpec := &common.LocalNodeSpec{Name: msg.Hostname}
	old, found := s.cache.NodeStatesByName[localNodeSpec.Name]
	if found {
		err = s.onNodeDeleted(old, localNodeSpec)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("node to delete not found")
	}
	return nil
}

func (s *Server) onNodeUpdated(old *common.LocalNodeSpec, node *common.LocalNodeSpec) (err error) {
	// This is used by the routing server to process Wireguard key updates
	// As a result we only send an event when a node is updated, not when it is added or deleted
	s.connectivityHandler.OnPeerNodeStateChanged(old, node)
	change := common.GetIPNetChangeType(old.IPv4Address, node.IPv4Address) | common.GetIPNetChangeType(old.IPv6Address, node.IPv6Address)
	if change&(common.ChangeDeleted|common.ChangeUpdated) != 0 && node.Name == *config.NodeName {
		// restart if our BGP config changed
		return NodeWatcherRestartError{}
	}
	if change != common.ChangeSame {
		s.configureRemoteNodeSnat(old, false /* isAdd */)
		s.configureRemoteNodeSnat(node, true /* isAdd */)
	}

	return nil
}

func (s *Server) onNodeAdded(node *common.LocalNodeSpec) (err error) {
	if node.Name == *config.NodeName &&
		(node.IPv4Address != nil || node.IPv6Address != nil) {
		if s.cache.GetNodeIP4() == nil && s.cache.GetNodeIP6() == nil {
			// this only happens once at startup
			// TODO: we should properly implement the node address update
			// for e.g. v4v6 independent updates.
			s.GotOurNodeBGPchan <- node
			s.cache.NodeBGPSpec = node
			err = s.felixLateInit()
			if err != nil {
				return errors.Wrap(err, "Error in felixLateInit")
			}
		}
	}
	s.connectivityHandler.OnPeerNodeStateChanged(nil /* old */, node)
	s.configureRemoteNodeSnat(node, true /* isAdd */)

	return nil
}

func (s *Server) configureRemoteNodeSnat(node *common.LocalNodeSpec, isAdd bool) {
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

func (s *Server) onNodeDeleted(old *common.LocalNodeSpec, node *common.LocalNodeSpec) error {
	s.connectivityHandler.OnPeerNodeStateChanged(old, nil /* new */)

	if old.Name == *config.NodeName {
		// restart if our BGP config changed
		return NodeWatcherRestartError{}
	}

	s.configureRemoteNodeSnat(old, false /* isAdd */)
	return nil
}
