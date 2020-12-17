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

package vpplink

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/wireguard"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) ListWireguardTunnels() ([]*types.WireguardTunnel, error) {
	tunnels, err := v.listWireguardTunnels(types.InvalidInterface)
	return tunnels, err
}

func (v *VppLink) GetWireguardTunnel(swIfIndex uint32) (*types.WireguardTunnel, error) {
	tunnels, err := v.listWireguardTunnels(interface_types.InterfaceIndex(swIfIndex))
	if err != nil {
		return nil, err
	}
	if len(tunnels) != 1 {
		return nil, errors.Errorf("Found %d Wireguard tunnels for swIfIndex %d", len(tunnels), swIfIndex)
	}
	return tunnels[0], nil
}

func (v *VppLink) listWireguardTunnels(swIfIndex interface_types.InterfaceIndex) ([]*types.WireguardTunnel, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	tunnels := make([]*types.WireguardTunnel, 0)
	request := &wireguard.WireguardInterfaceDump{
		ShowPrivateKey: false,
		SwIfIndex:      swIfIndex,
	}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &wireguard.WireguardInterfaceDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing Wireguard tunnels")
		}
		if stop {
			break
		}
		tunnels = append(tunnels, &types.WireguardTunnel{
			Port:      response.Interface.Port,
			Addr:      types.FromVppAddress(response.Interface.SrcIP),
			SwIfIndex: uint32(response.Interface.SwIfIndex),
			PublicKey: response.Interface.PublicKey,
		})
	}
	return tunnels, nil
}

func (v *VppLink) AddWireguardTunnel(tunnel *types.WireguardTunnel) (uint32, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &wireguard.WireguardInterfaceCreateReply{}
	request := &wireguard.WireguardInterfaceCreate{
		GenerateKey: true,
		Interface: wireguard.WireguardInterface{
			UserInstance: ^uint32(0),
			SwIfIndex:    types.InvalidInterface,
			Port:         tunnel.Port,
			SrcIP:        types.ToVppAddress(tunnel.Addr),
			PrivateKey:   tunnel.PrivateKey,
			PublicKey:    tunnel.PublicKey,
		},
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "Add Wireguard Tunnel failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("Add Wireguard Tunnel failed with retval %d", response.Retval)
	}
	tunnel.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DelWireguardTunnel(tunnel *types.WireguardTunnel) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &wireguard.WireguardInterfaceDeleteReply{}
	request := &wireguard.WireguardInterfaceDelete{
		SwIfIndex: interface_types.InterfaceIndex(tunnel.SwIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del Wireguard Tunnel %s failed", tunnel.String())
	} else if response.Retval != 0 {
		return fmt.Errorf("Del Wireguard Tunnel %s failed with retval %d", tunnel.String(), response.Retval)
	}
	return nil
}

func (v *VppLink) ListWireguardPeers() ([]*types.WireguardPeer, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	tunnels := make([]*types.WireguardPeer, 0)
	request := &wireguard.WireguardPeersDump{}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &wireguard.WireguardPeersDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing Wireguard peers")
		}
		if stop {
			break
		}
		allowedIps := make([]net.IPNet, 0)
		for _, aip := range response.Peer.AllowedIps {
			allowedIps = append(allowedIps, *types.FromVppPrefix(aip))
		}
		tunnels = append(tunnels, &types.WireguardPeer{
			Port:                response.Peer.Port,
			PersistentKeepalive: int(response.Peer.PersistentKeepalive),
			TableID:             response.Peer.TableID,
			Addr:                types.FromVppAddress(response.Peer.Endpoint),
			SwIfIndex:           uint32(response.Peer.SwIfIndex),
			PublicKey:           response.Peer.PublicKey,
			AllowedIps:          allowedIps,
		})
	}
	return tunnels, nil
}

func (v *VppLink) AddWireguardPeer(peer *types.WireguardPeer) (uint32, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	allowedIps := make([]ip_types.Prefix, 0)
	for _, aip := range peer.AllowedIps {
		allowedIps = append(allowedIps, types.ToVppPrefix(&aip))
	}
	ka := uint16(peer.PersistentKeepalive)
	if ka == 0 {
		ka = 1 /* default to 1 */
	}

	response := &wireguard.WireguardPeerAddReply{}
	request := &wireguard.WireguardPeerAdd{
		Peer: wireguard.WireguardPeer{
			PublicKey:           peer.PublicKey,
			Port:                peer.Port,
			PersistentKeepalive: ka,
			TableID:             peer.TableID,
			Endpoint:            types.ToVppAddress(peer.Addr),
			SwIfIndex:           interface_types.InterfaceIndex(peer.SwIfIndex),
			AllowedIps:          allowedIps,
		},
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "Add Wireguard Peer failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("Add Wireguard Peer failed with retval %d", response.Retval)
	}
	peer.Index = uint32(response.PeerIndex)
	return uint32(response.PeerIndex), nil
}

func (v *VppLink) DelWireguardPeer(peer *types.WireguardPeer) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &wireguard.WireguardPeerRemoveReply{}
	request := &wireguard.WireguardPeerRemove{
		PeerIndex: uint32(peer.Index),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del Wireguard Peer Tunnel %s failed", peer.String())
	} else if response.Retval != 0 {
		return fmt.Errorf("Del Wireguard Peer Tunnel %s failed with retval %d", peer.String(), response.Retval)
	}
	return nil
}
