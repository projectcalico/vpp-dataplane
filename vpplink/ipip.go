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

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~214-g61309b2f8/ipip"
	"github.com/pkg/errors"
)

func ipipAddressFromNetIP(addr net.IP) ipip.Address {
	var ip ipip.AddressUnion = ipip.AddressUnion{}
	if IsIP4(addr) {
		var ip4 ipip.IP4Address
		copy(ip4[:], addr.To4()[0:4])
		ip.SetIP4(ip4)
		return ipip.Address{
			Af: ipip.ADDRESS_IP4,
			Un: ip,
		}
	} else {
		var ip6 ipip.IP6Address
		copy(ip6[:], addr.To16())
		ip.SetIP6(ip6)
		return ipip.Address{
			Af: ipip.ADDRESS_IP6,
			Un: ip,
		}
	}
}

func (v *VppLink) AddIpipTunnel(src net.IP, dst net.IP, tableID uint32) (SwIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipAddTunnelReply{}
	request := &ipip.IpipAddTunnel{
		Tunnel: ipip.IpipTunnel{
			Instance: ^uint32(0),
			Src:      ipipAddressFromNetIP(src),
			Dst:      ipipAddressFromNetIP(dst),
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
		SwIfIndex: ipip.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del IPIP Tunnel %d failed", swIfIndex)
	} else if response.Retval != 0 {
		return fmt.Errorf("Del IPIP Tunnel %d failed with retval %d", swIfIndex, response.Retval)
	}
	return nil
}
