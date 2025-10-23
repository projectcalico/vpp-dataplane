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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/arp"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
)

func (v *VppLink) EnableArpProxy(swIfIndex, tableID uint32) error {
	client := arp.NewServiceClient(v.GetConnection())

	// First enable global arp proxy
	// set arp proxy table-id 0 start 0.0.0.0 end 255.255.255.255
	request := &arp.ProxyArpAddDel{
		IsAdd: true,
		Proxy: arp.ProxyArp{
			TableID: tableID,
			Low:     ip_types.IP4Address{0, 0, 0, 0},
			Hi:      ip_types.IP4Address{255, 255, 255, 255},
		},
	}
	_, err := client.ProxyArpAddDel(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("failed to add ProxyARP (%+v): %w", request, err)
	}

	_, err = client.ProxyArpIntfcEnableDisable(v.GetContext(), &arp.ProxyArpIntfcEnableDisable{
		Enable:    true,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to enable ProxyARP (swifidx %d): %w", swIfIndex, err)
	}
	return nil
}
