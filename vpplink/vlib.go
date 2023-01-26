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

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/vlib"
)

// GetNodeIndex gets node index of the node given by name. This is a helper method for VPP's node graph
// that process packets.
func (v *VppLink) GetNodeIndex(name string) (nodeIndex uint32, err error) {
	client := vlib.NewServiceClient(v.GetConnection())

	response, err := client.GetNodeIndex(v.GetContext(), &vlib.GetNodeIndex{
		NodeName: name,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get node index: %w", err)
	}
	return response.NodeIndex, nil
}

// AddNodeNext sets the next node for the node given by name in node graph. This is a helper method for VPP's
// node graph that process packets.
func (v *VppLink) AddNodeNext(name, next string) (nodeIndex uint32, err error) {
	client := vlib.NewServiceClient(v.GetConnection())

	response, err := client.AddNodeNext(v.GetContext(), &vlib.AddNodeNext{
		NodeName: name,
		NextName: next,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to add next node: %w", err)
	}
	return response.NextIndex, nil
}

// GetNumVPPWorkers gets the number of workers WITHOUT the main thread
func (v *VppLink) GetNumVPPWorkers() (numVPPWorkers int, err error) {
	client := vlib.NewServiceClient(v.GetConnection())

	response, err := client.ShowThreads(v.GetContext(), &vlib.ShowThreads{})
	if err != nil {
		return -1, fmt.Errorf("failed to get number of workers: %w", err)
	}
	return int(response.Count - 1), nil
}
