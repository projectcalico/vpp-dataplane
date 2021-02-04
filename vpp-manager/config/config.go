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
	"fmt"
	"net"
	"strings"

	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/vishvananda/netlink"
)

const (
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	VppConfigFile          = "/etc/vpp/startup.conf"
	VppConfigExecFile      = "/etc/vpp/startup.exec"
	VppManagerStatusFile   = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile   = "/var/run/vpp/vppmanagertap0"
	VppManagerLinuxMtu     = "/var/run/vpp/vppmanagerlinuxmtu"
	VppApiSocket           = "/var/run/vpp/vpp-api.sock"
	CalicoVppPidFile       = "/var/run/vpp/calico_vpp.pid"
	VppPath                = "/usr/bin/vpp"
	HostIfName             = "vpptap0"
	HostIfTag              = "hosttap"
	VppSigKillTimeout      = 2
)

const (
	DRIVER_UIO_PCI_GENERIC = "uio_pci_generic"
	DRIVER_VFIO_PCI        = "vfio-pci"
	DRIVER_VIRTIO_PCI      = "virtio-pci"
	DRIVER_I40E            = "i40e"
)

type VppManagerParams struct {
	VppStartupSleepSeconds int
	MainInterface          string
	ConfigExecTemplate     string
	ConfigTemplate         string
	InitScriptTemplate     string
	NodeName               string
	CorePattern            string
	RxMode                 types.RxMode
	TapRxMode              types.RxMode
	ServiceCIDRs           []net.IPNet
	VppIpConfSource        string
	ExtraAddrCount         int
	NativeDriver           string
	TapRxQueueSize         int
	TapTxQueueSize         int
	RxQueueSize            int
	TxQueueSize            int
	TapMtu                 int
	NumRxQueues            int
	NewDriverName          string
	DefaultGWs             []net.IP
	IfConfigSavePath       string
	EnableGSO              bool
	/* Capabilities */
	LoadedDrivers      map[string]bool
	KernelVersion      *KernelVersion
	AvailableHugePages int
	VfioUnsafeiommu    bool
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
	Mtu          int
}

type KernelVersion struct {
	Kernel int
	Major  int
	Minor  int
	Patch  int
}

func (ver *KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d-%d", ver.Kernel, ver.Major, ver.Minor, ver.Patch)
}

func (ver *KernelVersion) IsAtLeast(other *KernelVersion) bool {
	if ver.Kernel < other.Kernel {
		return false
	}
	if ver.Major < other.Major {
		return false
	}
	if ver.Minor < other.Minor {
		return false
	}
	if ver.Patch < other.Patch {
		return false
	}
	return true
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
