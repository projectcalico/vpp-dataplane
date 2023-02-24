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
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/vlib"
)

// GetNodeIndex gets node index of the node given by name. This is a helper method for VPP's node graph
// that process packets.
func (v *VppLink) GetNodeIndex(name string) (nodeIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vlib.GetNodeIndexReply{}
	request := &vlib.GetNodeIndex{
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

// AddNodeNext sets the next node for the node given by name in node graph. This is a helper method for VPP's
// node graph that process packets.
func (v *VppLink) AddNodeNext(name, next string) (nodeIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vlib.AddNodeNextReply{}
	request := &vlib.AddNodeNext{
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

// GetNumVPPWorkers gets the number of workers WITHOUT the main thread
func (v *VppLink) GetNumVPPWorkers() (numVPPWorkers int, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vlib.ShowThreadsReply{}
	request := &vlib.ShowThreads{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return -1, errors.Wrap(err, "GetNumVPPWorkers failed")
	} else if response.Retval != 0 {
		return -1, fmt.Errorf("GetNumVPPWorkers failed with retval %d", response.Retval)
	}
	return int(response.Count - 1), nil
}
