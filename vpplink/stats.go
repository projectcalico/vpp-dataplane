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

	interfaces "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface"
)

func (v *VppLink) GetBufferStats() (available uint32, cached uint32, used uint32, err error) {
	client := interfaces.NewServiceClient(v.GetConnection())

	response, err := client.GetBuffersStats(v.GetContext(), &interfaces.GetBuffersStats{})
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to get buffer stats: %w", err)
	}
	return response.AvailableBuffers, response.CachedBuffers, response.UsedBuffers, nil
}
