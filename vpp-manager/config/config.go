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
	"sort"
	"strconv"
	"strings"

	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/vishvananda/netlink"
)

const (
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	PuntTableId            = 1
	VppConfigFile          = "/etc/vpp/startup.conf"
	VppConfigExecFile      = "/etc/vpp/startup.exec"
	VppManagerStatusFile   = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile   = "/var/run/vpp/vppmanagertap0"
	VppManagerLinuxMtu     = "/var/run/vpp/vppmanagerlinuxmtu"
	VppApiSocket           = "/var/run/vpp/vpp-api.sock"
	CalicoVppPidFile       = "/var/run/vpp/calico_vpp.pid"
	VppPath                = "/usr/bin/vpp"
	VppSigKillTimeout      = 2
	DefaultEncapSize       = 60 // Used to lower the MTU of the routes to the cluster
)

const (
	DRIVER_UIO_PCI_GENERIC = "uio_pci_generic"
	DRIVER_VFIO_PCI        = "vfio-pci"
	DRIVER_VIRTIO_PCI      = "virtio-pci"
	DRIVER_I40E            = "i40e"
	DRIVER_MLX5_CORE       = "mlx5_core"
	DRIVER_VMXNET3         = "vmxnet3"
)

type InterfaceSpec struct {
	IsMain            bool
	InterfaceName   string `json:"interface"`
	VppIpConfSource string `json:"vppIpConfSource"`
	NativeDriver    string `json:"nativeDriver"`
	NewDriverName   string `json:"newDriver"`
	NumRxQueues     int    `json:"rx"`
	NumTxQueues     int    `json:"tx"`
	SwIfIndex       uint32
}

type VppManagerParams struct {
	VppStartupSleepSeconds   int
	InterfacesSpecs          []InterfaceSpec
	ConfigExecTemplate       string
	ConfigTemplate           string
	NodeName                 string
	CorePattern              string
	RxMode                   types.RxMode
	TapRxMode                types.RxMode
	ServiceCIDRs             []net.IPNet
	ExtraAddrCount           int
	TapRxQueueSize           int
	TapTxQueueSize           int
	RxQueueSize              int
	TxQueueSize              int
	UserSpecifiedMtu         int
	DefaultGWs               []net.IP
	IfConfigSavePath         string
	EnableGSO                bool
	IpsecNbAsyncCryptoThread int
	/* Capabilities */
	LoadedDrivers      map[string]bool
	KernelVersion      *KernelVersion
	AvailableHugePages int
	VfioUnsafeiommu    bool
}

type LinuxInterfaceState struct {
	PciId         string
	Driver        string
	IsUp          bool
	Addresses     []netlink.Addr
	Routes        []netlink.Route
	HardwareAddr  net.HardwareAddr
	PromiscOn     bool
	NumTxQueues   int
	NumRxQueues   int
	DoSwapDriver  bool
	Hasv4         bool
	Hasv6         bool
	NodeIP4       string
	NodeIP6       string
	Mtu           int
	InterfaceName string
}

type KernelVersion struct {
	Kernel int
	Major  int
	Minor  int
	Patch  int
}

func GetUplinkMtu(params *VppManagerParams, conf *LinuxInterfaceState, includeEncap bool) int {
	encapSize := 0
	if includeEncap {
		encapSize = DefaultEncapSize
	}
	// Use the linux interface MTU as default value if nothing is configured from env
	if params.UserSpecifiedMtu == 0 {
		return conf.Mtu - encapSize
	}
	return params.UserSpecifiedMtu - encapSize
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

func (c *LinuxInterfaceState) AddressString() string {
	var str []string
	for _, addr := range c.Addresses {
		str = append(str, addr.String())
	}
	return strings.Join(str, ",")
}

func (c *LinuxInterfaceState) RouteString() string {
	var str []string
	for _, route := range c.Routes {
		if route.Dst == nil {
			str = append(str, fmt.Sprintf("<Dst: nil (default), Ifindex: %d", route.LinkIndex))
			if route.Gw != nil {
				str = append(str, fmt.Sprintf("Gw: %s", route.Gw.String()))
			}
			if route.Src != nil {
				str = append(str, fmt.Sprintf("Src: %s", route.Src.String()))
			}
			str = append(str, ">")
		} else {
			str = append(str, route.String())
		}
	}
	return strings.Join(str, ", ")
}

// SortRoutes sorts the route slice by dependency order, so we can then add them
// in the order of the slice without issues
func (c *LinuxInterfaceState) SortRoutes() {
	sort.SliceStable(c.Routes, func(i, j int) bool {
		// Directly connected routes go first
		if c.Routes[i].Gw == nil {
			return true
		} else if c.Routes[j].Gw == nil {
			return false
		}
		// Default routes go last
		if c.Routes[i].Dst == nil {
			return false
		} else if c.Routes[j].Dst == nil {
			return true
		}
		// Finally sort by decreasing prefix length
		i_len, _ := c.Routes[i].Dst.Mask.Size()
		j_len, _ := c.Routes[j].Dst.Mask.Size()
		return i_len > j_len
	})
}

func TemplateScriptReplace(input string, params *VppManagerParams, conf []*LinuxInterfaceState) (template string) {
	template = input
	if conf != nil {
		/* We might template scripts before reading interface conf */
		template = strings.ReplaceAll(template, "__PCI_DEVICE_ID__", conf[0].PciId)
		for i, ifcConf := range conf {
			template = strings.ReplaceAll(template, "__PCI_DEVICE_ID_"+strconv.Itoa(i)+"__", ifcConf.PciId)
		}
	}
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", params.InterfacesSpecs[0].InterfaceName)
	for i, ifc := range params.InterfacesSpecs {
		template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF_"+fmt.Sprintf("%d", i)+"__", ifc.InterfaceName)
	}
	return template
}
