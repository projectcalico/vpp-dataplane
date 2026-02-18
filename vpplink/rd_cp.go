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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/rd_cp"
)

func (v *VppLink) enableDisableIP6NdAddressAutoconfig(swIfIndex uint32, enable bool) (err error) {
	client := rd_cp.NewServiceClient(v.GetConnection())

	_, err = client.IP6NdAddressAutoconfig(v.GetContext(), &rd_cp.IP6NdAddressAutoconfig{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Enable:    enable,
	})
	if err != nil {
		return fmt.Errorf("failed to call IP6NdAddressAutoconfig: %w", err)
	}
	return nil
}

func (v *VppLink) EnableIP6NdAddressAutoconfig(swIfIndex uint32) (err error) {
	return v.enableDisableIP6NdAddressAutoconfig(swIfIndex, true)
}

func (v *VppLink) DisableIP6NdAddressAutoconfig(swIfIndex uint32) (err error) {
	return v.enableDisableIP6NdAddressAutoconfig(swIfIndex, false)
}
