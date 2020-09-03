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

package types

import (
	"net"

	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-g3a42319eb/ip"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~361-g3a42319eb/ipsec"
)

type IPsecTunnelProtection struct {
	SwIfIndex   uint32
	NextHop     net.IP
	OutSAIndex  uint32
	InSAIndices []uint32
}

func FromVppIPsecAddress(vppAddr ipsec.Address) net.IP {
	return FromVppIpAddressUnion(vppip.AddressUnion(vppAddr.Un), vppAddr.Af == ipsec.ADDRESS_IP6)
}
