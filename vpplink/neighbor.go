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

package vpplink

import (
	"fmt"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_neighbor"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) AddNeighbor(neighbor *types.Neighbor) error {
	return v.addDelNeighbor(neighbor, true)
}

func (v *VppLink) DelNeighbor(neighbor *types.Neighbor) error {
	return v.addDelNeighbor(neighbor, false)
}

func (v *VppLink) addDelNeighbor(neighbor *types.Neighbor, isAdd bool) error {
	client := ip_neighbor.NewServiceClient(v.GetConnection())

	_, err := client.IPNeighborAddDel(v.GetContext(), &ip_neighbor.IPNeighborAddDel{
		IsAdd: isAdd,
		Neighbor: ip_neighbor.IPNeighbor{
			SwIfIndex:  interface_types.InterfaceIndex(neighbor.SwIfIndex),
			Flags:      types.ToVppNeighborFlags(neighbor.Flags),
			MacAddress: types.MacAddress(neighbor.HardwareAddr),
			IPAddress:  types.ToVppAddress(neighbor.IP),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to %s neighbor from VPP: %w", isAddStr(isAdd), err)
	}
	v.GetLog().Debugf("%sed neighbor %+v", isAddStr(isAdd), neighbor)
	return nil
}

func (v *VppLink) configureNeighbors(neighborConfig *types.NeighborConfig, isIP6 bool) error {
	client := ip_neighbor.NewServiceClient(v.GetConnection())
	_, err := client.IPNeighborConfig(v.GetContext(), &ip_neighbor.IPNeighborConfig{
		Af:        types.ToVppAddressFamily(isIP6),
		MaxNumber: neighborConfig.MaxNumber,
		MaxAge:    neighborConfig.MaxAge,
		Recycle:   neighborConfig.Recycle,
	})
	if err != nil {
		return fmt.Errorf("failed to set neighbor config in VPP: %s, %w", neighborConfig, err)
	}
	v.GetLog().Debugf("set neighbor config %s", neighborConfig)
	return nil
}

func (v *VppLink) ConfigureNeighborsV4(neighborConfig *types.NeighborConfig) error {
	return v.configureNeighbors(neighborConfig, false /* isIP6 */)
}

func (v *VppLink) ConfigureNeighborsV6(neighborConfig *types.NeighborConfig) error {
	return v.configureNeighbors(neighborConfig, true /* isIP6 */)
}
