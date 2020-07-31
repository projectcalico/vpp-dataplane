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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~215-g37bd1e445/ipsec"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/pkg/errors"
)

func (v *VppLink) GetIPsecTunnelProtection(tunnelInterface uint32) (protections []types.IPsecTunnelProtection, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &ipsec.IpsecTunnelProtectDump{
		SwIfIndex: ipsec.InterfaceIndex(tunnelInterface),
	}
	response := &ipsec.IpsecTunnelProtectDetails{}
	stream := v.ch.SendMultiRequest(request)
	for {
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing tunnel interface %u protections", tunnelInterface)
		}
		if stop {
			return protections, nil
		}
		p := response.Tun
		protections = append(protections, types.IPsecTunnelProtection{
			SwIfIndex:   uint32(p.SwIfIndex),
			NextHop:     types.FromVppIPsecAddress(p.Nh),
			OutSAIndex:  p.SaOut,
			InSAIndices: p.SaIn,
		})
	}
}
