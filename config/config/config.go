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
	"encoding/json"
	"net"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"

	"fmt"
	"sort"
	"strconv"

	"github.com/vishvananda/netlink"
)

const DefaultRxMode = types.Adaptative

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

func (i *InterfaceSpec) Validate(maxIfSpec *InterfaceSpec) error {
	if i.RxMode == types.UnknownRxMode {
		i.RxMode = DefaultRxMode
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
	IsMain        *bool  `json:"-"`
	InterfaceName string `json:"interfaceName"`
	VppDriver     string `json:"vppDriver"`
	NewDriverName string `json:"newDriver"`
	/* User specified MTU for uplink & the tap */
	Mtu       int `json:"mtu"`
	SwIfIndex uint32
}

func (u *UplinkInterfaceSpec) GetIsMain() bool {
	if u.IsMain == nil {
		return false
	}
	return *u.IsMain
}

func (u *UplinkInterfaceSpec) Validate(maxIfSpec *InterfaceSpec, isMain bool) error {
	if !isMain && u.VppDriver == "" {
		return errors.Errorf("vpp driver should be specified for secondary uplink interfaces")
	}
	return u.InterfaceSpec.Validate(maxIfSpec)
}

type CalicoVppDebug struct {
	PoliciesEnabled *bool `json:"policiesEnabled,omitempty"`
	ServicesEnabled *bool `json:"servicesEnabled,omitempty"`
	MaglevEnabled   *bool `json:"maglevEnabled,omitempty"`
	GSOEnabled      *bool `json:"gsoEnabled,omitempty"`
}

type CalicoVppFeatureGates struct {
	MemifEnabled    *bool `json:"memifEnabled,omitempty"`
	VCLEnabled      *bool `json:"vclEnabled,omitempty"`
	MultinetEnabled *bool `json:"multinetEnabled,omitempty"`
	SRv6Enabled     *bool `json:"srv6Enabled,omitempty"`
	IPSecEnabled    *bool `json:"ipsecEnabled,omitempty"`
}

type CalicoVppSrv6 struct {
	LocalsidPool string `json:"localsidPool"`
	PolicyPool   string `json:"policyPool"`
}

type CalicoVppIpsec struct {
	CrossIpsecTunnels    *bool `json:"crossIPSecTunnels,omitempty"`
	NbAsyncCryptoThreads int   `json:"nbAsyncCryptoThreads"`
	ExtraAddresses       int   `json:"extraAddresses"`
}

type CalicoVppInterfaces struct {
	DefaultPodIfSpec *InterfaceSpec        `json:"defaultPodIfSpec,omitempty"`
	MaxPodIfSpec     *InterfaceSpec        `json:"maxPodIfSpec,omitempty"`
	VppHostTapSpec   *InterfaceSpec        `json:"vppHostTapSpec,omitempty"`
	UplinkInterfaces []UplinkInterfaceSpec `json:"uplinkInterfaces,omitempty"`
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

const (
	CNIServerSocket      = "/var/run/calico/cni-server.sock"
	FelixDataplaneSocket = "/var/run/calico/felix-dataplane.sock"
	VppAPISocket         = "/var/run/vpp/vpp-api.sock"
	VppManagerInfoFile   = "/var/run/vpp/vppmanagerinfofile"
	CniServerStateFile   = "/var/run/vpp/calico_vpp_pod_state"
	CalicoVppPidFile     = "/var/run/vpp/calico_vpp.pid"

	NodeNameEnvVar      = "NODENAME"
	LogLevelEnvVar      = "CALICO_LOG_LEVEL"
	ServicePrefixEnvVar = "SERVICE_PREFIX"
	IPSecIkev2PskEnvVar = "CALICOVPP_IPSEC_IKEV2_PSK"

	CalicoVppInitialConfigEnvVar = "CALICOVPP_INITIAL_CONFIG"
	CalicoVppInterfacesEnvVar    = "CALICOVPP_INTERFACES"
	CalicoVppIpsecEnvVar         = "CALICOVPP_IPSEC"
	CalicoVppSrv6EnvVar          = "CALICOVPP_SRV6"
	CalicoVppFeatureGatesEnvVar  = "CALICOVPP_FEATURE_GATES"
	CalicoVppDebugEnvVar         = "CALICOVPP_DEBUG"

	MemifSocketName      = "@vpp/memif"
	DefaultVXLANVni      = 4096
	DefaultVXLANPort     = 4789
	DefaultWireguardPort = 51820
)

var (
	/* disable by default as it might impact security */
	MultinetEnabled = false
	/* disable by default as it might impact security */
	MemifEnabled = false
	/* disable by default as it might impact security */
	VCLEnabled               = false
	PodGSOEnabled            = true
	EnableMaglev             = true
	EnableServices           = true
	EnablePolicies           = true
	EnableIPSec              = false
	EnableSRv6               = false
	IpsecAddressCount        = 1
	CrossIpsecTunnels        = false
	IPSecIkev2Psk            = ""
	BgpLogLevel              = logrus.InfoLevel
	LogLevel                 = logrus.InfoLevel
	NodeName                 = ""
	ServiceCIDRs             []*net.IPNet
	IpsecNbAsyncCryptoThread int = 0
	SRv6policyIPPool             = ""
	SRv6localSidIPPool           = ""

	DefaultInterfaceSpec InterfaceSpec = InterfaceSpec{NumRxQueues: 1, NumTxQueues: 1, RxQueueSize: 0, TxQueueSize: 0}
	MaxPodIfSpec         *InterfaceSpec
)

func PrintAgentConfig(log *logrus.Logger) {
	log.Infof("Config:MultinetEnabled   %t", MultinetEnabled)
	log.Infof("Config:MemifEnabled      %t", MemifEnabled)
	log.Infof("Config:VCLEnabled        %t", VCLEnabled)
	log.Infof("Config:PodGSOEnabled     %t", PodGSOEnabled)
	log.Infof("Config:EnableServices    %t", EnableServices)
	log.Infof("Config:EnableIPSec       %t", EnableIPSec)
	log.Infof("Config:CrossIpsecTunnels %t", CrossIpsecTunnels)
	log.Infof("Config:EnablePolicies    %t", EnablePolicies)
	log.Infof("Config:IpsecAddressCount %d", IpsecAddressCount)
	log.Infof("Config:LogLevel          %d", LogLevel)
	log.Infof("Config:IpsecNbAsyncCryptoThread  %d", IpsecNbAsyncCryptoThread)
	log.Infof("Config:EnableSRv6        %t", EnableSRv6)
}

var supportedEnvVars map[string]bool

func isEnvVarSupported(str string) bool {
	_, found := supportedEnvVars[str]
	return found
}

func getEnvValue(str string) string {
	supportedEnvVars[str] = true
	return os.Getenv(str)
}

func GetBool(poin *bool, defaultVal bool) bool {
	if poin == nil {
		return defaultVal
	}
	return *poin
}

// LoadConfig loads the calico-vpp-agent configuration from the environment
func LoadConfig(log *logrus.Logger) (err error) {
	supportedEnvVars = make(map[string]bool)

	if conf := getEnvValue(LogLevelEnvVar); conf != "" {
		loglevel, err := logrus.ParseLevel(conf)
		if err != nil {
			log.WithError(err).Errorf("Failed to parse loglevel: %s, defaulting to info", conf)
		} else {
			LogLevel = loglevel
		}
	}

	NodeName = getEnvValue(NodeNameEnvVar)

	var calicoVppInterfaces CalicoVppInterfaces
	conf := getEnvValue(CalicoVppInterfacesEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppInterfaces)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppInterfacesEnvVar, conf, err)
		}
	}

	var calicoVppFeatureGates CalicoVppFeatureGates
	conf = getEnvValue(CalicoVppFeatureGatesEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppFeatureGates)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppFeatureGatesEnvVar, conf, err)
		}
	}

	var calicoVppIpsec CalicoVppIpsec
	conf = getEnvValue(CalicoVppIpsecEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppIpsec)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppIpsecEnvVar, conf, err)
		}
	}

	var calicoVppDebug CalicoVppDebug
	conf = getEnvValue(CalicoVppDebugEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppDebug)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppDebugEnvVar, conf, err)
		}
	}

	var calicoVppSrv6 CalicoVppSrv6
	conf = getEnvValue(CalicoVppSrv6EnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppSrv6)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppSrv6EnvVar, conf, err)
		}
	}

	if calicoVppInterfaces.MaxPodIfSpec != nil {
		calicoVppInterfaces.MaxPodIfSpec.Validate(nil)
		MaxPodIfSpec = calicoVppInterfaces.MaxPodIfSpec
	}
	if calicoVppInterfaces.DefaultPodIfSpec != nil {
		if err := calicoVppInterfaces.DefaultPodIfSpec.Validate(MaxPodIfSpec); err != nil {
			return errors.Errorf("default pod interface spec exceeds max interface spec: %s", err)
		} else {
			DefaultInterfaceSpec = *calicoVppInterfaces.DefaultPodIfSpec
			isL3 := DefaultInterfaceSpec.GetIsL3(false)
			DefaultInterfaceSpec.IsL3 = &isL3
		}
	}

	VCLEnabled = GetBool(calicoVppFeatureGates.VCLEnabled, VCLEnabled)
	MemifEnabled = GetBool(calicoVppFeatureGates.MemifEnabled, MemifEnabled)
	MultinetEnabled = GetBool(calicoVppFeatureGates.MultinetEnabled, MultinetEnabled)
	PodGSOEnabled = GetBool(calicoVppDebug.GSOEnabled, PodGSOEnabled)
	EnableIPSec = GetBool(calicoVppFeatureGates.IPSecEnabled, EnableIPSec)
	EnableServices = GetBool(calicoVppDebug.ServicesEnabled, EnableServices)
	EnableMaglev = GetBool(calicoVppDebug.MaglevEnabled, EnableMaglev)
	EnablePolicies = GetBool(calicoVppDebug.PoliciesEnabled, EnablePolicies)
	CrossIpsecTunnels = GetBool(calicoVppIpsec.CrossIpsecTunnels, CrossIpsecTunnels)
	EnableSRv6 = GetBool(calicoVppFeatureGates.SRv6Enabled, EnableSRv6)

	SRv6localSidIPPool = calicoVppSrv6.LocalsidPool
	SRv6policyIPPool = calicoVppSrv6.PolicyPool
	IpsecNbAsyncCryptoThread = calicoVppIpsec.NbAsyncCryptoThreads
	extraAddressCount := calicoVppIpsec.ExtraAddresses
	IpsecAddressCount = int(extraAddressCount) + 1

	psk := getEnvValue(IPSecIkev2PskEnvVar)
	if EnableIPSec && psk == "" {
		return errors.New("IKEv2 PSK not configured: nothing found in CALICOVPP_IPSEC_IKEV2_PSK environment variable")
	}
	IPSecIkev2Psk = psk

	servicePrefixStr := getEnvValue(ServicePrefixEnvVar)
	for _, prefixStr := range strings.Split(servicePrefixStr, ",") {
		_, serviceCIDR, err := net.ParseCIDR(prefixStr)
		if err != nil {
			return errors.Errorf("invalid service prefix configuration: %s %s", prefixStr, err)
		}
		ServiceCIDRs = append(ServiceCIDRs, serviceCIDR)
	}
	return nil
}

const (
	VppConfigFile     = "/etc/vpp/startup.conf"
	VppConfigExecFile = "/etc/vpp/startup.exec"
	VppApiSocket      = "/var/run/vpp/vpp-api.sock"
	VppPath           = "/usr/bin/vpp"
	VppNetnsName      = "calico-vpp-ns"
	VppSigKillTimeout = 2
	DefaultEncapSize  = 60 // Used to lower the MTU of the routes to the cluster
)

const (
	DRIVER_UIO_PCI_GENERIC = "uio_pci_generic"
	DRIVER_VFIO_PCI        = "vfio-pci"
	DRIVER_VIRTIO_PCI      = "virtio-pci"
	DRIVER_I40E            = "i40e"
	DRIVER_ICE             = "ice"
	DRIVER_MLX5_CORE       = "mlx5_core"
	DRIVER_VMXNET3         = "vmxnet3"
)

var Info = &VppManagerInfo{}

type vppManagerStatus string

const (
	Ready    vppManagerStatus = "ready"
	Starting vppManagerStatus = "starting"
)

type UplinkStatus struct {
	SwIfIndex    uint32
	TapSwIfIndex uint32
	LinkIndex    int
	Name         string
	IsMain       bool
	Mtu          int
}

type VppManagerInfo struct {
	Status         vppManagerStatus
	UplinkStatuses []UplinkStatus
	FakeNextHopIP4 net.IP
	FakeNextHopIP6 net.IP
}

func (i *VppManagerInfo) GetMainSwIfIndex() uint32 {
	for _, u := range i.UplinkStatuses {
		if u.IsMain {
			return u.SwIfIndex
		}
	}
	return vpplink.INVALID_SW_IF_INDEX
}

type VppManagerParams struct {
	VppStartupSleepSeconds   int
	UplinksSpecs             []UplinkInterfaceSpec
	DefaultTap               InterfaceSpec
	ConfigExecTemplate       string
	ConfigTemplate           string
	NodeName                 string
	CorePattern              string
	ServiceCIDRs             []net.IPNet
	ExtraAddrCount           int
	DefaultGWs               []net.IP
	IfConfigSavePath         string
	EnableGSO                bool
	IpsecNbAsyncCryptoThread int
	/* Capabilities */
	LoadedDrivers      map[string]bool
	KernelVersion      *KernelVersion
	AvailableHugePages int
	VfioUnsafeiommu    bool

	NodeAnnotations map[string]string
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
	IsTunTap      bool
	IsVeth        bool
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
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", params.UplinksSpecs[0].InterfaceName)
	for i, ifc := range params.UplinksSpecs {
		template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF_"+fmt.Sprintf("%d", i)+"__", ifc.InterfaceName)
	}
	for key, value := range params.NodeAnnotations {
		template = strings.ReplaceAll(template, fmt.Sprintf("__NODE_ANNOTATION:%s__", key), value)
	}
	return template
}
