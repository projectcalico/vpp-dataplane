// Copyright (C) 2021 Cisco Systems Inc.
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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/pbl"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) AddPblClient(pblClient *types.PblClient) (id uint32, err error) {
	client := pbl.NewServiceClient(v.GetConnection())

	portRanges := make([]pbl.PblPortRange, 0, len(pblClient.PortRanges))
	for _, r := range pblClient.PortRanges {
		portRanges = append(portRanges, pbl.PblPortRange{
			Start:  r.Start,
			End:    r.End,
			Iproto: types.ToVppIPProto(r.Proto),
		})
	}

	response, err := client.PblClientUpdate(v.GetContext(), &pbl.PblClientUpdate{
		Client: pbl.PblClient{
			ID:         pblClient.ID,
			TableID:    pblClient.TableId,
			Addr:       types.ToVppAddress(pblClient.Addr),
			Paths:      pblClient.Path.ToFibPath(false),
			Flags:      0,
			PortRanges: portRanges,
		},
	})
	if err != nil {
		return 0, fmt.Errorf("failed to update Pbl Client: %w", err)
	}
	pblClient.ID = response.ID
	return response.ID, nil
}

func (v *VppLink) DelPblClient(id uint32) error {
	client := pbl.NewServiceClient(v.GetConnection())

	_, err := client.PblClientDel(v.GetContext(), &pbl.PblClientDel{
		ID: id,
	})
	if err != nil {
		return fmt.Errorf("failed to delete Pbl Client: %w", err)
	}
	return nil
}
