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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/vxlan"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) ListVXLanTunnels() ([]*types.VXLanTunnel, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	tunnels := make([]*types.VXLanTunnel, 0)
	request := &vxlan.VxlanTunnelV2Dump{
		SwIfIndex: types.InvalidInterface,
	}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &vxlan.VxlanTunnelV2Details{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing VXLan tunnels")
		}
		if stop {
			break
		}
		tunnels = append(tunnels, &types.VXLanTunnel{
			SrcAddress:     types.FromVppAddress(response.SrcAddress),
			DstAddress:     types.FromVppAddress(response.DstAddress),
			SrcPort:        response.SrcPort,
			DstPort:        response.DstPort,
			Vni:            response.Vni,
			DecapNextIndex: response.DecapNextIndex,
			SwIfIndex:      response.SwIfIndex,
		})
	}
	return tunnels, nil
}
func (v *VppLink) addDelVXLanTunnel(tunnel *types.VXLanTunnel, isAdd bool) (swIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vxlan.VxlanAddDelTunnelV3Reply{}
	request := &vxlan.VxlanAddDelTunnelV3{
		IsAdd:          isAdd,
		Instance:       ^uint32(0),
		SrcAddress:     types.ToVppAddress(tunnel.SrcAddress),
		DstAddress:     types.ToVppAddress(tunnel.DstAddress),
		SrcPort:        tunnel.SrcPort,
		DstPort:        tunnel.DstPort,
		Vni:            tunnel.Vni,
		DecapNextIndex: tunnel.DecapNextIndex,
		IsL3:           true,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	opStr := "Del"
	if isAdd {
		opStr = "Add"
	}
	if err != nil {
		return ^uint32(1), errors.Wrapf(err, "%s vxlan Tunnel failed", opStr)
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("%s vxlan Tunnel failed with retval %d", opStr, response.Retval)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) AddVXLanTunnel(tunnel *types.VXLanTunnel) (swIfIndex uint32, err error) {
	return v.addDelVXLanTunnel(tunnel, true)
}

func (v *VppLink) DelVXLanTunnel(tunnel *types.VXLanTunnel) (err error) {
	_, err = v.addDelVXLanTunnel(tunnel, false)
	return err
}
