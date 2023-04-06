// Copyright (C) 2023 Cisco Systems Inc.
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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/wireguard"

	typesv0 "github.com/calico-vpp/vpplink/api/v0"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
)

func (v *VppLink) ListWireguardTunnels() ([]*typesv0.WireguardTunnel, error) {
	tunnels, err := v.listWireguardTunnels(interface_types.InterfaceIndex(typesv0.InvalidInterface))
	return tunnels, err
}

func (v *VppLink) GetWireguardTunnel(swIfIndex uint32) (*typesv0.WireguardTunnel, error) {
	tunnels, err := v.listWireguardTunnels(interface_types.InterfaceIndex(swIfIndex))
	if err != nil {
		return nil, err
	}
	if len(tunnels) != 1 {
		return nil, fmt.Errorf("found %d Wireguard tunnels for swIfIndex %d", len(tunnels), swIfIndex)
	}
	return tunnels[0], nil
}

func (v *VppLink) listWireguardTunnels(swIfIndex interface_types.InterfaceIndex) ([]*typesv0.WireguardTunnel, error) {
	client := wireguard.NewServiceClient(v.GetConnection())

	stream, err := client.WireguardInterfaceDump(v.GetContext(), &wireguard.WireguardInterfaceDump{
		ShowPrivateKey: true,
		SwIfIndex:      swIfIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list Wireguard tunnels: %w", err)
	}
	var tunnels []*typesv0.WireguardTunnel
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list Wireguard tunnels: %w", err)
		}
		tunnels = append(tunnels, &typesv0.WireguardTunnel{
			Port:       response.Interface.Port,
			Addr:       response.Interface.SrcIP.ToIP(),
			SwIfIndex:  uint32(response.Interface.SwIfIndex),
			PublicKey:  response.Interface.PublicKey,
			PrivateKey: response.Interface.PrivateKey,
		})
	}
	return tunnels, nil
}
