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

package vpplink

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ipip"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) ListIPIPTunnels() ([]*types.IPIPTunnel, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	tunnels := make([]*types.IPIPTunnel, 0)
	request := &ipip.IpipTunnelDump{
		SwIfIndex: types.InvalidInterface,
	}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &ipip.IpipTunnelDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing IPIP tunnels")
		}
		if stop {
			break
		}
		tunnels = append(tunnels, &types.IPIPTunnel{
			Src:       types.FromVppAddress(response.Tunnel.Src),
			Dst:       types.FromVppAddress(response.Tunnel.Dst),
			TableID:   response.Tunnel.TableID,
			SwIfIndex: uint32(response.Tunnel.SwIfIndex),
		})
	}
	return tunnels, nil
}

func (v *VppLink) AddIPIPTunnel(tunnel *types.IPIPTunnel) (uint32, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipAddTunnelReply{}
	request := &ipip.IpipAddTunnel{
		Tunnel: ipip.IpipTunnel{
			Instance: ^uint32(0),
			Src:      types.ToVppAddress(tunnel.Src),
			Dst:      types.ToVppAddress(tunnel.Dst),
			TableID:  tunnel.TableID,
		},
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "Add IPIP Tunnel failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("Add IPIP Tunnel failed with retval %d", response.Retval)
	}
	tunnel.SwIfIndex = uint32(response.SwIfIndex)
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DelIPIPTunnel(tunnel *types.IPIPTunnel) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipDelTunnelReply{}
	request := &ipip.IpipDelTunnel{
		SwIfIndex: interface_types.InterfaceIndex(tunnel.SwIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del IPIP Tunnel %s failed", tunnel.String())
	} else if response.Retval != 0 {
		return fmt.Errorf("Del IPIP Tunnel %s failed with retval %d", tunnel.String(), response.Retval)
	}
	return nil
}
