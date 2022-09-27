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

package common_config

import "github.com/projectcalico/vpp-dataplane/vpplink/types"

const DefaultRxMode = types.Adaptative

type InterfaceSpec struct {
	NumRxQueues int  `json:"rx"`
	NumTxQueues int  `json:"tx"`
	RxQueueSize int  `json:"rxqsz"`
	TxQueueSize int  `json:"txqsz"`
	IsL3        bool `json:"isl3"`
	/* "interrupt" "adaptive" or "polling" mode */
	RxMode string `json:"rxMode"`
}

func GetRxMode(rxModeString string) types.RxMode {
	rxMode := types.UnformatRxMode(rxModeString)
	if rxMode == types.UnknownRxMode {
		rxMode = DefaultRxMode
	}
	return rxMode
}

type UplinkInterfaceSpec struct {
	InterfaceSpec
	IsMain          *bool  `json:"isMain,omitempty"`
	InterfaceName   string `json:"interface"`
	VppIpConfSource string `json:"vppIpConfSource"`
	NativeDriver    string `json:"nativeDriver"`
	NewDriverName   string `json:"newDriver"`
	SwIfIndex       uint32 `json:-`
}

type CalicoVppDebug struct {
	PoliciesEnabled *bool `json:"policiesEnabled,omitempty"`
	ServicesEnabled *bool `json:"servicesEnabled,omitempty"`
	MaglevEnabled   *bool `json:"maglevEnabled,omitempty"`
	GSOEnabled      *bool `json:"GSOEnabled,omitempty"`
}

type CalicoVppFeatureGates struct {
	MemifEnabled    *bool `json:"memifEnabled,omitempty"`
	VCLEnabled      *bool `json:"vCLEnabled,omitempty"`
	MultinetEnabled *bool `json:"multinetEnabled,omitempty"`
	SRv6Enabled     *bool `json:"SRv6Enabled,omitempty"`
	IPSecEnabled    *bool `json:"IPSecEnabled,omitempty"`
}

type CalicoVppSrv6 struct {
	LocalsidPool string `json:"localsidPool"`
	PolicyPool   string `json:"policyPool"`
}

type CalicoVppIpsec struct {
	CrossIpsecTunnels    *bool `json:"crossIPSecTunnels,omitempty"`
	NbAsyncCryptoThreads int   `json:"NbAsyncCryptoThreads"`
	ExtraAddresses       int   `json:"ExtraAddresses"`
}

type CalicoVppInterfaces struct {
	/* User specified MTU for uplink & the tap */
	Mtu int `json:"Mtu"`
	/* Queue size (either "1024" or "1024,512" for rx,tx) for the tap/the uplink */
	RingSize string `json:"ringSize"`

	DefaultPodIfSpec *InterfaceSpec         `json:"defaultPodIfSpec,omitempty"`
	MaxIfSpec        *InterfaceSpec         `json:"maxIfSpec,omitempty"`
	VppHostTapSpec   *InterfaceSpec         `json:"vppHostTapSpec,omitempty"`
	UplinkInterfaces *[]UplinkInterfaceSpec `json:"uplinkInterfaces,omitempty"`
}

type CalicoVppInitialConfig struct { //out of agent and vppmanager
	VppStartupSleepSeconds int `json:"vppStartupSleepSeconds"`
	/* Set the pattern for VPP corefiles. Usually "/var/lib/vpp/vppcore.%e.%p" */
	CorePattern      string `json:"corePattern"`
	ExtraAddrCount   int    `json:"extraAddrCount"`
	IfConfigSavePath string `json:"ifConfigSavePath"`
	/* Comma separated list of IPs to be configured in VPP as default GW */
	DefaultGWs string `json:"defaultGWs"`
}

func NotExceedMax(ifSpec InterfaceSpec, max InterfaceSpec) bool {
	if max.NumRxQueues == 0 && max.NumTxQueues == 0 && max.RxQueueSize == 0 && max.TxQueueSize == 0 {
		return true
	}
	return ifSpec.NumRxQueues <= max.NumRxQueues && ifSpec.NumTxQueues <= max.NumTxQueues &&
		ifSpec.RxQueueSize <= max.RxQueueSize && ifSpec.TxQueueSize <= max.TxQueueSize
}
