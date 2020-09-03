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
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-gab9444728/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-gab9444728/ipip"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) AddIpipTunnel(src net.IP, dst net.IP, tableID uint32) (SwIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipAddTunnelReply{}
	request := &ipip.IpipAddTunnel{
		Tunnel: ipip.IpipTunnel{
			Instance: ^uint32(0),
			Src:      types.ToVppAddress(src),
			Dst:      types.ToVppAddress(dst),
			TableID:  0,
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "Add IPIP Tunnel failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("Add IPIP Tunnel failed with retval %d", response.Retval)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DelIpipTunnel(swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipDelTunnelReply{}
	request := &ipip.IpipDelTunnel{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del IPIP Tunnel %d failed", swIfIndex)
	} else if response.Retval != 0 {
		return fmt.Errorf("Del IPIP Tunnel %d failed with retval %d", swIfIndex, response.Retval)
	}
	return nil
}
