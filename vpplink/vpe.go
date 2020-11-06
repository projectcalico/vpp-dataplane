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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/vpe"
)

func (v *VppLink) GetNodeIndex(name string) (nodeIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vpe.GetNodeIndexReply{}
	request := &vpe.GetNodeIndex{
		NodeName: name,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "GetNodeIndex failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("GetNodeIndex failed with retval %d", response.Retval)
	}
	return uint32(response.NodeIndex), nil
}

func (v *VppLink) AddNodeNext(name, next string) (nodeIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vpe.AddNodeNextReply{}
	request := &vpe.AddNodeNext{
		NodeName: name,
		NextName: next,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "AddNodeNext failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("AddNodeNext failed with retval %d", response.Retval)
	}
	return uint32(response.NextIndex), nil
}

/* Gets the number of workers WITHOUT the main thread */
func (v *VppLink) GetNumVPPWorkers() (numVPPWorkers uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vpe.ShowThreadsReply{}
	request := &vpe.ShowThreads{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "GetNumVPPWorkers failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("GetNumVPPWorkers failed with retval %d", response.Retval)
	}
	return uint32(response.Count - 1), nil
}
