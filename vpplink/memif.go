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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/memif"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) addDelMemifSocketFileName(socketFileName string, socketId uint32, isAdd bool) (uint32, error) {
	v.Lock()
	defer v.Unlock()
	response := &memif.MemifSocketFilenameAddDelV2Reply{}
	request := &memif.MemifSocketFilenameAddDelV2{
		IsAdd:          isAdd,
		SocketFilename: socketFileName,
		SocketID:       socketId,
	}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return 0, errors.Wrapf(err, "MemifSocketFilenameAddDel failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return 0, fmt.Errorf("MemifSocketFilenameAddDel failed (retval %d). Request: %+v", response.Retval, request)
	}
	return response.SocketID, nil
}

func (v *VppLink) AddMemifSocketFileName(socketFileName string) (uint32, error) {
	socketId, err := v.addDelMemifSocketFileName(socketFileName, ^uint32(0), true /* isAdd */)
	return socketId, err
}

func (v *VppLink) DelMemifSocketFileName(socketId uint32) error {
	_, err := v.addDelMemifSocketFileName("", socketId, false /* isAdd */)
	return err
}

func (v *VppLink) ListMemifSockets() ([]*types.MemifSocket, error) {
	v.Lock()
	defer v.Unlock()

	sockets := make([]*types.MemifSocket, 0)
	request := &memif.MemifSocketFilenameDump{}
	stream := v.GetChannel().SendMultiRequest(request)
	for {
		response := &memif.MemifSocketFilenameDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing memif sockets")
		}
		if stop {
			break
		}
		sockets = append(sockets, &types.MemifSocket{
			SocketID:       response.SocketID,
			SocketFilename: response.SocketFilename,
		})
	}
	return sockets, nil
}

func (v *VppLink) DeleteMemif(swIfIndex uint32) (err error) {
	v.Lock()
	defer v.Unlock()
	response := &memif.MemifDeleteReply{}
	request := &memif.MemifDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "DeleteMemif failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("DeleteMemif failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *VppLink) CreateMemif(mif *types.Memif) error {
	v.Lock()
	defer v.Unlock()
	response := &memif.MemifCreateReply{}
	request := &memif.MemifCreate{
		Role:       memif.MemifRole(mif.Role),
		Mode:       memif.MemifMode(mif.Mode),
		RxQueues:   uint8(mif.NumRxQueues),
		TxQueues:   uint8(mif.NumTxQueues),
		SocketID:   mif.SocketId,
		BufferSize: uint16(mif.QueueSize),
	}
	if mif.MacAddress != nil {
		request.HwAddr = types.ToVppMacAddress(&mif.MacAddress)
	}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "MemifCreate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("MemifCreate failed (retval %d). Request: %+v", response.Retval, request)
	}
	mif.SwIfIndex = uint32(response.SwIfIndex)
	return nil
}

func (v *VppLink) ListMemifInterfaces() ([]*types.Memif, error) {
	v.Lock()
	defer v.Unlock()

	memifs := make([]*types.Memif, 0)
	request := &memif.MemifDump{}
	stream := v.GetChannel().SendMultiRequest(request)
	for {
		response := &memif.MemifDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing memifs")
		}
		if stop {
			break
		}
		memifs = append(memifs, &types.Memif{
			SwIfIndex: uint32(response.SwIfIndex),
			Role:      types.MemifRole(response.Role),
			Mode:      types.MemifMode(response.Mode),
			SocketId:  response.SocketID,
			QueueSize: int(response.BufferSize),
			Flags:     types.MemifFlag(response.Flags),
		})
	}
	return memifs, nil
}

func (v *VppLink) MemifsocketByID(socketID uint32) (*types.MemifSocket, error) {
	sockets, err := v.ListMemifSockets()
	if err != nil {
		return nil, errors.Wrapf(err, "error listing memif sockets")
	}
	for _, socket := range sockets {
		if socket.SocketID == socketID {
			return socket, nil
		}
	}
	return nil, fmt.Errorf("can't find socket with id %d", socketID)
}
