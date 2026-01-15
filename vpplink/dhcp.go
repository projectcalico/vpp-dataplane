// Copyright (C) 2026 Cisco Systems Inc.
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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/dhcp"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// SetDHCPv6Proxy configures VPP as a DHCPv6 relay agent.
// This allows VPP to relay DHCPv6 messages from clients on the rxVrfID
// to a DHCPv6 server reachable via serverVrfID.
//
// Parameters:
// - rxVrfID: VRF where DHCPv6 client traffic arrives (client-facing side)
// - serverVrfID: VRF where the DHCPv6 server is reachable
// - serverAddr: IPv6 address of the DHCPv6 server
// - srcAddr: Source IPv6 address for relay-forward messages to the server
// - isAdd: true to add, false to delete
//
// Per RFC 8415, the relay will:
// - Set peer-address to the client's source address
// - Set link-address to identify the client's link for address pool selection
// - Include Interface-Id option for reply demultiplexing
func (v *VppLink) SetDHCPv6Proxy(rxVrfID, serverVrfID uint32, serverAddr, srcAddr net.IP, isAdd bool) error {
	client := dhcp.NewServiceClient(v.GetConnection())

	_, err := client.DHCPProxyConfig(v.GetContext(), &dhcp.DHCPProxyConfig{
		RxVrfID:        rxVrfID,
		ServerVrfID:    serverVrfID,
		IsAdd:          isAdd,
		DHCPServer:     types.ToVppAddress(serverAddr),
		DHCPSrcAddress: types.ToVppAddress(srcAddr),
	})
	if err != nil {
		action := "add"
		if !isAdd {
			action = "delete"
		}
		return fmt.Errorf("failed to %s DHCPv6 proxy (rxVrf=%d, serverVrf=%d, server=%s, src=%s): %w",
			action, rxVrfID, serverVrfID, serverAddr, srcAddr, err)
	}

	v.GetLog().Infof("Configured DHCPv6 proxy: rxVrf=%d, serverVrf=%d, server=%s, src=%s, isAdd=%v",
		rxVrfID, serverVrfID, serverAddr, srcAddr, isAdd)
	return nil
}

// AddDHCPv6Proxy is a convenience wrapper for SetDHCPv6Proxy with isAdd=true
func (v *VppLink) AddDHCPv6Proxy(rxVrfID, serverVrfID uint32, serverAddr, srcAddr net.IP) error {
	return v.SetDHCPv6Proxy(rxVrfID, serverVrfID, serverAddr, srcAddr, true)
}

// DelDHCPv6Proxy is a convenience wrapper for SetDHCPv6Proxy with isAdd=false
func (v *VppLink) DelDHCPv6Proxy(rxVrfID, serverVrfID uint32, serverAddr, srcAddr net.IP) error {
	return v.SetDHCPv6Proxy(rxVrfID, serverVrfID, serverAddr, srcAddr, false)
}
