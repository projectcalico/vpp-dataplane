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

package types

import (
	"net"
)

type PblPortRange struct {
	Start uint16
	End   uint16
	Proto IPProto
}

type PblClient struct {
	ID         uint32
	TableID    uint32
	Addr       net.IP
	Path       RoutePath
	PortRanges []PblPortRange
}
