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
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func IsIP4(ip net.IP) bool {
	return types.IsIP4(ip)
}

func IsIP6(ip net.IP) bool {
	return types.IsIP6(ip)
}

func AddrFamilyDiffers(addr1 net.IP, addr2 net.IP) bool {
	if IsIP4(addr1) && IsIP4(addr2) || IsIP6(addr1) && IsIP6(addr2) {
		return true
	}
	return false
}
