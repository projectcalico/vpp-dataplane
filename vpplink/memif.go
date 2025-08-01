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
	"io"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/memif"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) addDelMemifSocketFileName(socketFileName string, socketID uint32, isAdd bool) (uint32, error) {
	client := memif.NewServiceClient(v.GetConnection())

	response, err := client.MemifSocketFilenameAddDelV2(v.GetContext(), &memif.MemifSocketFilenameAddDelV2{
		IsAdd:          isAdd,
		SocketFilename: socketFileName,
		SocketID:       socketID,
	})
	if err != nil {
		return 0, fmt.Errorf("memifSocketFilenameAddDel failed: %w", err)
	}
	return response.SocketID, nil
}

func (v *VppLink) AddMemifSocketFileName(socketFileName string) (uint32, error) {
	socketID, err := v.addDelMemifSocketFileName(socketFileName, ^uint32(0), true /* isAdd */)
	return socketID, err
}

func (v *VppLink) DelMemifSocketFileName(socketID uint32) error {
	_, err := v.addDelMemifSocketFileName("", socketID, false /* isAdd */)
	return err
}

func (v *VppLink) ListMemifSockets() ([]*types.MemifSocket, error) {
	client := memif.NewServiceClient(v.GetConnection())

	stream, err := client.MemifSocketFilenameDump(v.GetContext(), &memif.MemifSocketFilenameDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump memif sockets: %w", err)
	}
	sockets := make([]*types.MemifSocket, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump memif sockets: %w", err)
		}
		sockets = append(sockets, &types.MemifSocket{
			SocketID:       response.SocketID,
			SocketFilename: response.SocketFilename,
		})
	}
	return sockets, nil
}

func (v *VppLink) DeleteMemif(swIfIndex uint32) error {
	client := memif.NewServiceClient(v.GetConnection())

	_, err := client.MemifDelete(v.GetContext(), &memif.MemifDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("deleteMemif failed: %w", err)
	}
	return nil
}

func (v *VppLink) CreateMemif(mif *types.Memif) error {
	client := memif.NewServiceClient(v.GetConnection())

	request := &memif.MemifCreate{
		Role:       memif.MemifRole(mif.Role),
		Mode:       memif.MemifMode(mif.Mode),
		RxQueues:   uint8(mif.NumRxQueues),
		TxQueues:   uint8(mif.NumTxQueues),
		SocketID:   mif.SocketID,
		BufferSize: uint16(mif.QueueSize),
	}
	if mif.MacAddress != nil {
		request.HwAddr = types.MacAddress(mif.MacAddress)
	}
	response, err := client.MemifCreate(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("memifCreate failed: %w", err)
	}
	mif.SwIfIndex = uint32(response.SwIfIndex)
	return nil
}

func (v *VppLink) ListMemifInterfaces() ([]*types.Memif, error) {
	client := memif.NewServiceClient(v.GetConnection())

	stream, err := client.MemifDump(v.GetContext(), &memif.MemifDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump memif interfaces: %w", err)
	}
	memifs := make([]*types.Memif, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump memif interfaces: %w", err)
		}
		memifs = append(memifs, &types.Memif{
			SwIfIndex: uint32(response.SwIfIndex),
			Role:      types.MemifRole(response.Role),
			Mode:      types.MemifMode(response.Mode),
			SocketID:  response.SocketID,
			QueueSize: int(response.BufferSize),
			Flags:     types.MemifFlag(response.Flags),
		})
	}
	return memifs, nil
}

func (v *VppLink) MemifsocketByID(socketID uint32) (*types.MemifSocket, error) {
	sockets, err := v.ListMemifSockets()
	if err != nil {
		return nil, fmt.Errorf("error listing memif sockets: %w", err)
	}
	for _, socket := range sockets {
		if socket.SocketID == socketID {
			return socket, nil
		}
	}
	return nil, fmt.Errorf("can't find socket with id %d", socketID)
}
