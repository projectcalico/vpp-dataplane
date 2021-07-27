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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/memif"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) addDelMemifSocketFileName(socketFileName string, namespace string, socketId uint32, isAdd bool) (uint32, error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &memif.MemifSocketFilenameAddDelV2Reply{}
	request := &memif.MemifSocketFilenameAddDelV2{
		IsAdd:          isAdd,
		SocketFilename: socketFileName,
		Namespace:      namespace,
		SocketID:       socketId,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return 0, errors.Wrapf(err, "MemifSocketFilenameAddDel failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return 0, fmt.Errorf("MemifSocketFilenameAddDel failed (retval %d). Request: %+v", response.Retval, request)
	}
	return response.SocketID, nil
}

func (v *VppLink) AddMemifSocketFileName(socketFileName string, namespace string) (uint32, error) {
	socketId, err := v.addDelMemifSocketFileName(socketFileName, namespace, ^uint32(0), true /* isAdd */)
	return socketId, err
}

func (v *VppLink) DelMemifSocketFileName(socketId uint32) error {
	_, err := v.addDelMemifSocketFileName("", "", socketId, false /* isAdd */)
	return err
}

func (v *VppLink) DeleteMemif(mif *types.Memif) error {
	var err2 error = nil
	if mif.SocketId != 0 {
		err2 = v.DelMemifSocketFileName(mif.SocketId)
	}
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &memif.MemifDeleteReply{}
	request := &memif.MemifDelete{
		SwIfIndex: interface_types.InterfaceIndex(mif.SwIfIndex),
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "DeleteMemif failed: req %+v reply %+v (%s)", request, response, err2)
	} else if response.Retval != 0 {
		return fmt.Errorf("DeleteMemif failed (retval %d). Request: %+v (%s)", response.Retval, request, err2)
	}
	return err2
}

func (v *VppLink) CreateMemif(mif *types.Memif) error {
	socketId, err := v.AddMemifSocketFileName(mif.SocketFileName, mif.Namespace)
	if err != nil {
		return err
	}
	mif.SocketId = socketId
	response := &memif.MemifCreateReply{}
	request := &memif.MemifCreate{
		Role:       memif.MemifRole(mif.Role),
		Mode:       memif.MemifMode(mif.Mode),
		RxQueues:   uint8(mif.NumRxQueues),
		TxQueues:   uint8(mif.NumTxQueues),
		SocketID:   socketId,
		BufferSize: uint16(mif.QueueSize),
	}
	if mif.MacAddress != nil {
		request.HwAddr = types.ToVppMacAddress(&mif.MacAddress)
	}
	v.lock.Lock()
	err = v.ch.SendRequest(request).ReceiveReply(response)
	v.lock.Unlock()
	/* don't defer as memifSocket call also locks */
	if err != nil {
		err2 := v.DelMemifSocketFileName(socketId)
		return errors.Wrapf(err, "MemifCreate failed: req %+v reply %+v (cleanup %s)", request, response, err2)
	} else if response.Retval != 0 {
		err2 := v.DelMemifSocketFileName(socketId)
		return fmt.Errorf("MemifCreate failed (retval %d). Request: %+v (cleanup %s)", response.Retval, request, err2)
	}
	mif.SwIfIndex = uint32(response.SwIfIndex)
	return nil
}
