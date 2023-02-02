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
	"net"

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/ip6_nd"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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

func (v *VppLink) EnableIP6NdProxy(swIfIndex uint32, address net.IP) error {
	client := ip6_nd.NewServiceClient(v.GetConnection())

	_, err := client.IP6ndProxyAddDel(v.GetContext(), &ip6_nd.IP6ndProxyAddDel{
		IsAdd:     true,
		IP:        types.ToVppIP6Address(address),
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to add IP6 ND Proxy address %v (swif %d): %w", address, swIfIndex, err)
	}

	// now disable source / dest checks for nd proxy
	_, err = client.IP6ndProxyEnableDisable(v.GetContext(), &ip6_nd.IP6ndProxyEnableDisable{
		IsEnable:  true,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to enable IP6 ND Proxy (swif %d): %w", swIfIndex, err)
	}

	return nil
}
