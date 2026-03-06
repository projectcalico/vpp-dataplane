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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip6_nd"
)

func (v *VppLink) DisableIP6RouterAdvertisements(swIfIndex uint32) error {
	client := ip6_nd.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceIP6ndRaConfig(v.GetContext(), &ip6_nd.SwInterfaceIP6ndRaConfig{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Suppress:  1,
	})
	if err != nil {
		return fmt.Errorf("failed to disable IP6 ND RA (swif %d): %w", swIfIndex, err)
	}
	return nil
}

func (v *VppLink) EnableIP6NdProxy(swIfIndex uint32) error {
	client := ip6_nd.NewServiceClient(v.GetConnection())

	_, err := client.IP6ndProxyEnableDisableV2(v.GetContext(), &ip6_nd.IP6ndProxyEnableDisableV2{
		IsEnable:  true,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Flags:     1, // IP6_ND_PROXY_IF_FLAG_NO_DST_FILTER
	})
	if err != nil {
		return fmt.Errorf("failed to enable IP6 ND Proxy (swif %d): %w", swIfIndex, err)
	}

	return nil
}
