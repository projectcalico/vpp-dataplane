// Copyright (C) 2020 Cisco Systems Inc.
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
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/vishvananda/netlink"
	"net"
	"strings"
)

const (
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	VppConfigFile          = "/etc/vpp/startup.conf"
	VppConfigExecFile      = "/etc/vpp/startup.exec"
	VppManagerStatusFile   = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile   = "/var/run/vpp/vppmanagertap0"
	VppApiSocket           = "/var/run/vpp/vpp-api.sock"
	CalicoVppPidFile       = "/var/run/vpp/calico_vpp.pid"
	VppPath                = "/usr/bin/vpp"
	HostIfName             = "vpptap0"
	HostIfTag              = "hosttap"
	VppSigKillTimeout      = 2
)

type VppManagerParams struct {
	VppStartupSleepSeconds  int
	MainInterface           string
	ConfigExecTemplate      string
	ConfigTemplate          string
	InitScriptTemplate      string
	NodeName                string
	CorePattern             string
	RxMode                  types.RxMode
	TapRxMode               types.RxMode
	ServiceCIDRs            []net.IPNet
	VppIpConfSource         string
	ExtraAddrCount          int
	VppSideMacAddress       net.HardwareAddr
	ContainerSideMacAddress net.HardwareAddr
	NativeDriver            string
	TapRxQueueSize          int
	TapTxQueueSize          int
	RxQueueSize             int
	TxQueueSize             int
	NumRxQueues             int
	NewDriverName           string
	DefaultGWs              []net.IP
	IfConfigSavePath        string
	/* Capabilities */
	AreDriverLoaded     bool
	KernelSupportsAfXDP bool
	AvailableHugePages  int
}

type InterfaceConfig struct {
	PciId        string
	Driver       string
	IsUp         bool
	Addresses    []netlink.Addr
	Routes       []netlink.Route
	HardwareAddr net.HardwareAddr
	PromiscOn    bool
	NumTxQueues  int
	NumRxQueues  int
	DoSwapDriver bool
	Hasv4        bool
	Hasv6        bool
	NodeIP4      string
	NodeIP6      string
}

func (c *InterfaceConfig) AddressString() string {
	var str []string
	for _, addr := range c.Addresses {
		str = append(str, addr.String())
	}
	return strings.Join(str, ",")
}

func (c *InterfaceConfig) RouteString() string {
	var str []string
	for _, route := range c.Routes {
		if route.Dst == nil {
			str = append(str, "<nil Dst>")
		} else {
			str = append(str, route.String())
		}
	}
	return strings.Join(str, ",")
}
