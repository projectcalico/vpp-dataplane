// Copyright (C) 2022 Cisco Systems Inc.
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

package config

import (
	_ "embed"
	"encoding/json"
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

type InterfaceSpec struct {
	NumRxQueues int   `json:"rx"`
	NumTxQueues int   `json:"tx"`
	RxQueueSize int   `json:"rxqsz"`
	TxQueueSize int   `json:"txqsz"`
	IsL3        *bool `json:"isl3"`
	/* "interrupt" "adaptive" or "polling" mode */
	RxMode types.RxMode `json:"rxMode"`
}

func (i *InterfaceSpec) GetIsL3(isMemif bool) bool {
	if i.IsL3 != nil {
		return *i.IsL3
	}
	return !isMemif //default value is true for tuntap and false for memif
}

func (i *InterfaceSpec) GetBuffersNeeded() uint64 {
	return uint64(i.NumRxQueues*i.RxQueueSize + i.NumTxQueues*i.TxQueueSize)
}

func (i *InterfaceSpec) String() string {
	b, _ := json.MarshalIndent(i, "", "  ")
	return string(b)
}

func (i *InterfaceSpec) GetRxModeWithDefault(defaultRxMode types.RxMode) types.RxMode {
	if i.RxMode == types.UnknownRxMode {
		return defaultRxMode
	}
	return i.RxMode
}

func (i *InterfaceSpec) Validate(maxIfSpec *InterfaceSpec) error {
	if i == nil {
		return nil // we allow to call (nil).Validate()
	}
	if i.NumRxQueues == 0 {
		i.NumRxQueues = 1
	}
	if i.NumTxQueues == 0 {
		i.NumTxQueues = 1
	}
	if i.RxQueueSize == 0 {
		i.RxQueueSize = 1024
	}
	if i.TxQueueSize == 0 {
		i.TxQueueSize = 1024
	}
	if maxIfSpec == nil {
		return nil
	}
	if (i.NumRxQueues > maxIfSpec.NumRxQueues && maxIfSpec.NumRxQueues > 0) ||
		(i.NumTxQueues > maxIfSpec.NumTxQueues && maxIfSpec.NumTxQueues > 0) ||
		(i.RxQueueSize > maxIfSpec.RxQueueSize && maxIfSpec.RxQueueSize > 0) ||
		(i.TxQueueSize > maxIfSpec.TxQueueSize && maxIfSpec.TxQueueSize > 0) {
		return errors.Errorf("interface config %+v exceeds max config: %+v", *i, maxIfSpec)
	}
	return nil
}

type UplinkInterfaceSpec struct {
	InterfaceSpec
	IsMain              bool              `json:"isMain"`
	PhysicalNetworkName string            `json:"physicalNetworkName"`
	InterfaceName       string            `json:"interfaceName"`
	VppDriver           string            `json:"vppDriver"`
	NewDriverName       string            `json:"newDriver"`
	Annotations         map[string]string `json:"annotations"`
	// IPFamilies declares which IP families are expected on this uplink.
	// Accepted values: "IPv4", "IPv6", "IPv4,IPv6". Defaults to "IPv4,IPv6".
	// This ensures the expected addresses are present and avoids a race condition
	// between DHCPv6 address assignment and VPP startup.
	IPFamilies IPFamilyConfig `json:"ipFamilies,omitempty"`
	// Mtu is the User specified MTU for uplink & the tap
	Mtu       int    `json:"mtu"`
	SwIfIndex uint32 `json:"-"`

	// uplinkInterfaceIndex is the index of the uplinkInterface in the list
	uplinkInterfaceIndex int `json:"-"`
}

func (u *UplinkInterfaceSpec) GetVppSideHardwareAddress() net.HardwareAddr {
	mac, _ := net.ParseMAC(BaseVppSideHardwareAddress)
	mac[len(mac)-1] = byte(u.uplinkInterfaceIndex)
	if u.uplinkInterfaceIndex > 255 {
		panic("too many uplinkinteraces")
	}
	return mac
}

func (u *UplinkInterfaceSpec) SetUplinkInterfaceIndex(uplinkInterfaceIndex int) {
	u.uplinkInterfaceIndex = uplinkInterfaceIndex
}

func (u *UplinkInterfaceSpec) Validate(maxIfSpec *InterfaceSpec) (err error) {
	if !u.IsMain && u.VppDriver == "" {
		return errors.Errorf("vpp driver should be specified for secondary uplink interfaces")
	}
	if err = u.IPFamilies.Validate(); err != nil {
		return err
	}
	return u.InterfaceSpec.Validate(maxIfSpec)
}

func (u *UplinkInterfaceSpec) String() string {
	b, _ := json.MarshalIndent(u, "", "  ")
	return string(b)
}
