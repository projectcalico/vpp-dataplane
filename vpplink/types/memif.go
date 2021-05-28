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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/memif"
	"net"
)

type MemifRole uint32
type MemifMode uint32

const (
	MemifMaster MemifRole = MemifRole(memif.MEMIF_ROLE_API_MASTER)
	MemifSlave  MemifRole = MemifRole(memif.MEMIF_ROLE_API_MASTER)

	MemifModeEthernet      MemifMode = MemifMode(memif.MEMIF_MODE_API_ETHERNET)
	MemifModeApiIP         MemifMode = MemifMode(memif.MEMIF_MODE_API_IP)
	MemifModeApiPuntInject MemifMode = MemifMode(memif.MEMIF_MODE_API_PUNT_INJECT)
)

type Memif struct {
	Role           MemifRole
	Mode           MemifMode
	NumRxQueues    int
	NumTxQueues    int
	QueueSize      int
	MacAddress     net.HardwareAddr
	SocketId       uint32
	SocketFileName string
	Namespace      string
	SwIfIndex      uint32
}
