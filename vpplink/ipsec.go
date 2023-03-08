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
	"io"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ipsec"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) GetIPsecTunnelProtection(tunnelInterface uint32) ([]types.IPsecTunnelProtection, error) {
	client := ipsec.NewServiceClient(v.GetConnection())

	stream, err := client.IpsecTunnelProtectDump(v.GetContext(), &ipsec.IpsecTunnelProtectDump{
		SwIfIndex: interface_types.InterfaceIndex(tunnelInterface),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump tunnel interface (%v) protections: %w", tunnelInterface, err)
	}
	protections := make([]types.IPsecTunnelProtection, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump tunnel interface (%v) protections: %w", tunnelInterface, err)
		}
		p := response.Tun
		protections = append(protections, types.IPsecTunnelProtection{
			SwIfIndex:   uint32(p.SwIfIndex),
			NextHop:     types.FromVppAddress(p.Nh),
			OutSAIndex:  p.SaOut,
			InSAIndices: p.SaIn,
		})
	}
	return protections, nil
}

func (v *VppLink) SetIPsecAsyncMode(enable bool) error {
	client := ipsec.NewServiceClient(v.GetConnection())

	_, err := client.IpsecSetAsyncMode(v.GetContext(), &ipsec.IpsecSetAsyncMode{
		AsyncEnable: enable,
	})
	if err != nil {
		return fmt.Errorf("failed to %v IPsec async mode: %w", strEnableDisable[enable], err)
	}
	return nil
}
