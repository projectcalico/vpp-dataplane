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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/classify"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) addDelClassifyTable(table *types.ClassifyTable, action types.ClassifyAction) (uint32, error) {
	client := classify.NewServiceClient(v.GetConnection())

	isAdd, delChain := false, false
	currentDataFlags := uint8(0)
	tableIndex := types.InvalidTableID
	switch action {
	case types.AddAbsolute:
		isAdd = true
	case types.AddRelative:
		isAdd = true
		currentDataFlags = uint8(1)
	case types.Del:
		tableIndex = table.TableIndex
	case types.DelChain:
		tableIndex = table.TableIndex
		delChain = true
	}

	mask := ExtendToVector(table.Mask)

	matchNVectors := table.MatchNVectors
	if matchNVectors == 0 {
		matchNVectors = uint32(len(mask)) / types.VectorSize
	}

	nBuckets := table.NBuckets
	if nBuckets == 0 {
		// We provide as many buckets as the max number of entries we expect in the table
		nBuckets = table.MaxNumEntries
	}

	memorySize := table.MemorySize
	if memorySize == 0 {
		/* memory needed for the table:
		*  - each entry has a size of (32-bytes + mask vectors)
		*  - up to 2 entries per page for collision resolution
		*  - double for margin
		 */
		memorySize = table.MaxNumEntries * (32 + matchNVectors*types.VectorSize) * 2 * 2
	}

	response, err := client.ClassifyAddDelTable(v.GetContext(), &classify.ClassifyAddDelTable{
		IsAdd:             isAdd,
		DelChain:          delChain,
		TableIndex:        tableIndex,
		Nbuckets:          nBuckets,
		MemorySize:        memorySize,
		SkipNVectors:      table.SkipNVectors,
		MatchNVectors:     matchNVectors,
		NextTableIndex:    table.NextTableIndex,
		MissNextIndex:     table.MissNextIndex,
		CurrentDataFlag:   currentDataFlags,
		CurrentDataOffset: table.CurrentDataOffset,
		MaskLen:           uint32(len(mask)),
		Mask:              mask,
	})

	if err != nil {
		return types.InvalidID, fmt.Errorf("failed to %s the classify table: %w", map[bool]string{true: "add", false: "del"}[isAdd], err)
	}

	return response.NewTableIndex, nil
}

func (v *VppLink) AddClassifyTable(table *types.ClassifyTable) (uint32, error) {
	return v.addDelClassifyTable(table, types.AddRelative)
}

func (v *VppLink) DelClassifyTable(tableIndex uint32) error {
	_, err := v.addDelClassifyTable(&types.ClassifyTable{TableIndex: tableIndex}, types.Del)
	return err
}

func ExtendToVector(match []byte) []byte {
	n := len(match) % types.VectorSize
	if n != 0 {
		match = match[:len(match)+types.VectorSize-n]
	}
	return match
}

func (v *VppLink) SetClassifyInputInterfaceTables(swIfIndex uint32, ip4TableIndex uint32, ip6TableIndex uint32, l2TableIndex uint32, isAdd bool) error {
	client := classify.NewServiceClient(v.GetConnection())

	_, err := client.InputACLSetInterface(v.GetContext(), &classify.InputACLSetInterface{
		IsAdd:         isAdd,
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		IP4TableIndex: ip4TableIndex,
		IP6TableIndex: ip6TableIndex,
		L2TableIndex:  l2TableIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to set input acl tables for this interface: %w", err)
	}
	return nil
}

func (v *VppLink) SetClassifyOutputInterfaceTables(swIfIndex uint32, ip4TableIndex uint32, ip6TableIndex uint32, l2TableIndex uint32, isAdd bool) error {
	client := classify.NewServiceClient(v.GetConnection())

	_, err := client.OutputACLSetInterface(v.GetContext(), &classify.OutputACLSetInterface{
		IsAdd:         isAdd,
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		IP4TableIndex: ip4TableIndex,
		IP6TableIndex: ip6TableIndex,
		L2TableIndex:  l2TableIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to set input acl tables for this interface: %w", err)
	}
	return nil
}
