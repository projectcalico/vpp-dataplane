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
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	CNIServerSocket      = "/var/run/calico/cni-server.sock"
	FelixDataplaneSocket = "/var/run/calico/felix-dataplane.sock"
	VppAPISocket         = "/var/run/vpp/vpp-api.sock"
	VppManagerInfoFile   = "/var/run/vpp/vppmanagerinfofile"
	CniServerStateFile   = "/var/run/vpp/calico_vpp_pod_state"
	CalicoVppPidFile     = "/var/run/vpp/calico_vpp.pid"
	CalicoVppVersionFile = "/etc/calicovppversion"

	DefaultVXLANVni      = 4096
	DefaultVXLANPort     = 4789
	DefaultWireguardPort = 51820

	VppConfigFile     = "/etc/vpp/startup.conf"
	VppConfigExecFile = "/etc/vpp/startup.exec"
	VppPath           = "/usr/bin/vpp"
	VppNetnsName      = "calico-vpp-ns"
	VppSigKillTimeout = 2
	DefaultEncapSize  = 60 // Used to lower the MTU of the routes to the cluster

	DefaultPhysicalNetworkName = ""

	// BaseVppSideHardwareAddress is the base hardware address of VPP side of the HostPunt
	// tap interface. It is used to generate hardware addresses for each uplink interface.
	BaseVppSideHardwareAddress = "02:ca:11:c0:fd:00"
)

var (
	// fake constants for place where we need a pointer to true or false
	True  = true
	False = false

	NodeName    = RequiredStringEnvVar("NODENAME")
	LogLevel    = EnvVar("CALICOVPP_LOG_LEVEL", logrus.InfoLevel, logrus.ParseLevel)
	BGPLogLevel = EnvVar("CALICOVPP_BGP_LOG_LEVEL", apipb.SetLogLevelRequest_INFO, BGPLogLevelParse)

	ServiceCIDRs                     = PrefixListEnvVar("SERVICE_PREFIX")
	IPSecIkev2Psk                    = StringEnvVar("CALICOVPP_IPSEC_IKEV2_PSK", "")
	CalicoVppDebug                   = JSONEnvVar("CALICOVPP_DEBUG", &CalicoVppDebugConfigType{})
	CalicoVppInterfaces              = JSONEnvVar("CALICOVPP_INTERFACES", &CalicoVppInterfacesConfigType{})
	CalicoVppFeatureGates            = JSONEnvVar("CALICOVPP_FEATURE_GATES", &CalicoVppFeatureGatesConfigType{})
	CalicoVppIpsec                   = JSONEnvVar("CALICOVPP_IPSEC", &CalicoVppIpsecConfigType{})
	CalicoVppSrv6                    = JSONEnvVar("CALICOVPP_SRV6", &CalicoVppSrv6ConfigType{})
	CalicoVppInitialConfig           = JSONEnvVar("CALICOVPP_INITIAL_CONFIG", &CalicoVppInitialConfigConfigType{})
	CalicoVppGracefulShutdownTimeout = EnvVar("CALICOVPP_GRACEFUL_SHUTDOWN_TIMEOUT", 10*time.Second, time.ParseDuration)
	LogFormat                        = StringEnvVar("CALICOVPP_LOG_FORMAT", "")

	/* Deprecated vars */
	/* linux name of the uplink interface to be used by VPP */
	InterfaceVar = StringEnvVar("CALICOVPP_INTERFACE", "")
	/* Driver to consume the uplink with. Leave empty for autoconf */
	NativeDriver = StringEnvVar("CALICOVPP_NATIVE_DRIVER", "")
	SwapDriver   = StringEnvVar("CALICOVPP_SWAP_DRIVER", "")

	/* Bash script template run before getting config
	   from $CALICOVPP_INTERFACE (same as
	   CALICOVPP_HOOK_BEFORE_IF_READ)*/
	InitScriptTemplate = StringEnvVar("CALICOVPP_INIT_SCRIPT_TEMPLATE", "")

	/* Template for VppConfigFile (/etc/vpp/startup.conf)
	   It contains the VPP startup configuration */
	ConfigTemplate = RequiredStringEnvVar("CALICOVPP_CONFIG_TEMPLATE")

	/* Template for VppConfigExecFile (/etc/vpp/startup.exec)
	   It contains the CLI to be executed in vppctl after startup */
	ConfigExecTemplate = StringEnvVar("CALICOVPP_CONFIG_EXEC_TEMPLATE", "")

	// Default hook script. This script contains various platform/os dependent
	// fixes/customizations/tweaks/hacks required for a successful deployment and
	// running of VPP. It can be overridden by setting the environment variables
	// below in the vpp-manager container.

	//go:embed default_hook.sh
	DefaultHookScript string

	/* Run this before getLinuxConfig() in case this is a script
	 * that's responsible for creating the interface */
	HookScriptBeforeIfRead = StringEnvVar("CALICOVPP_HOOK_BEFORE_IF_READ", DefaultHookScript) // InitScriptTemplate
	/* Bash script template run just after getting config
	   from $CALICOVPP_INTERFACE & before starting VPP */
	HookScriptBeforeVppRun = StringEnvVar("CALICOVPP_HOOK_BEFORE_VPP_RUN", DefaultHookScript) // InitPostIfScriptTemplate
	/* Bash script template run after VPP has started */
	HookScriptVppRunning = StringEnvVar("CALICOVPP_HOOK_VPP_RUNNING", DefaultHookScript) // FinalizeScriptTemplate
	/* Bash script template run when VPP stops gracefully */
	HookScriptVppDoneOk = StringEnvVar("CALICOVPP_HOOK_VPP_DONE_OK", DefaultHookScript)
	/* Bash script template run when VPP stops with an error */
	HookScriptVppErrored = StringEnvVar("CALICOVPP_HOOK_VPP_ERRORED", DefaultHookScript)

	AllHooks = []*string{
		HookScriptBeforeIfRead,
		HookScriptBeforeVppRun,
		HookScriptVppRunning,
		HookScriptVppDoneOk,
		HookScriptVppErrored,
	}

	Info = &VppManagerInfo{}

	// VppHostPuntFakeGatewayAddress is the fake gateway we use with a static neighbor
	// in the punt table to route punted packets to the host
	VppHostPuntFakeGatewayAddress = net.ParseIP("169.254.0.1")
)

func RunHook(hookScript *string, hookName string, params *VppManagerParams, log *logrus.Logger) {
	if *hookScript == "" {
		return
	}
	template, err := TemplateScriptReplace(*hookScript, params, nil)
	if err != nil {
		log.Warnf("Running hook %s errored with %s", hookName, err)
		return
	}

	cmd := exec.Command("/bin/bash", "-c", template, hookName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Warnf("Running hook %s errored with %s", hookName, err)
		return
	}
}

func GetCalicoVppDebug() *CalicoVppDebugConfigType                 { return *CalicoVppDebug }
func GetCalicoVppInterfaces() *CalicoVppInterfacesConfigType       { return *CalicoVppInterfaces }
func GetCalicoVppFeatureGates() *CalicoVppFeatureGatesConfigType   { return *CalicoVppFeatureGates }
func GetCalicoVppIpsec() *CalicoVppIpsecConfigType                 { return *CalicoVppIpsec }
func GetCalicoVppSrv6() *CalicoVppSrv6ConfigType                   { return *CalicoVppSrv6 }
func GetCalicoVppInitialConfig() *CalicoVppInitialConfigConfigType { return *CalicoVppInitialConfig }

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
	return u.InterfaceSpec.Validate(maxIfSpec)
}

func (u *UplinkInterfaceSpec) String() string {
	b, _ := json.MarshalIndent(u, "", "  ")
	return string(b)
}

type RedirectToHostRulesConfigType struct {
	Port uint16 `json:"port,omitempty"`
	IP   string `json:"ip,omitempty"`
	/* "tcp", "udp",... */
	Proto types.IPProto `json:"proto,omitempty"`
}

type CalicoVppDebugConfigType struct {
	PoliciesEnabled         *bool `json:"policiesEnabled,omitempty"`
	ServicesEnabled         *bool `json:"servicesEnabled,omitempty"`
	GSOEnabled              *bool `json:"gsoEnabled,omitempty"`
	SpreadTxQueuesOnWorkers *bool `json:"spreadTxQueuesOnWorkers,omitempty"`
}

func (cfg *CalicoVppDebugConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func (cfg *CalicoVppDebugConfigType) Validate() (err error) {
	if cfg.PoliciesEnabled == nil {
		cfg.PoliciesEnabled = &True
	}
	if cfg.ServicesEnabled == nil {
		cfg.ServicesEnabled = &True
	}
	if cfg.GSOEnabled == nil {
		cfg.GSOEnabled = &True
	}
	if cfg.SpreadTxQueuesOnWorkers == nil {
		cfg.SpreadTxQueuesOnWorkers = &False
	}
	return
}

type CalicoVppFeatureGatesConfigType struct {
	MemifEnabled      *bool `json:"memifEnabled,omitempty"`
	VCLEnabled        *bool `json:"vclEnabled,omitempty"`
	MultinetEnabled   *bool `json:"multinetEnabled,omitempty"`
	SRv6Enabled       *bool `json:"srv6Enabled,omitempty"`
	IPSecEnabled      *bool `json:"ipsecEnabled,omitempty"`
	PrometheusEnabled *bool `json:"prometheusEnabled,omitempty"`
}

func (cfg *CalicoVppFeatureGatesConfigType) Validate() (err error) {
	cfg.MemifEnabled = DefaultToPtr(cfg.MemifEnabled, true)
	cfg.VCLEnabled = DefaultToPtr(cfg.VCLEnabled, false)
	cfg.MultinetEnabled = DefaultToPtr(cfg.MultinetEnabled, false)
	cfg.SRv6Enabled = DefaultToPtr(cfg.SRv6Enabled, false)
	cfg.IPSecEnabled = DefaultToPtr(cfg.IPSecEnabled, false)
	cfg.PrometheusEnabled = DefaultToPtr(cfg.PrometheusEnabled, false)
	return nil
}

func (cfg *CalicoVppFeatureGatesConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

type CalicoVppSrv6ConfigType struct {
	LocalsidPool string `json:"localsidPool"`
	PolicyPool   string `json:"policyPool"`
}

func (cfg *CalicoVppSrv6ConfigType) Validate() (err error) { return nil }

func (cfg *CalicoVppSrv6ConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

type CalicoVppIpsecConfigType struct {
	CrossIpsecTunnels        *bool `json:"crossIPSecTunnels,omitempty"`
	IpsecNbAsyncCryptoThread int   `json:"nbAsyncCryptoThreads"`
	ExtraAddresses           int   `json:"extraAddresses"`
}

func (cfg *CalicoVppIpsecConfigType) GetIpsecNbAsyncCryptoThread() int {
	return cfg.IpsecNbAsyncCryptoThread
}

func (cfg *CalicoVppIpsecConfigType) Validate() (err error) {
	cfg.CrossIpsecTunnels = DefaultToPtr(cfg.CrossIpsecTunnels, false)
	return
}

func (cfg *CalicoVppIpsecConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func (cfg *CalicoVppIpsecConfigType) GetIpsecAddressCount() int {
	return cfg.ExtraAddresses + 1
}

type CalicoVppInterfacesConfigType struct {
	DefaultPodIfSpec *InterfaceSpec        `json:"defaultPodIfSpec,omitempty"`
	MaxPodIfSpec     *InterfaceSpec        `json:"maxPodIfSpec,omitempty"`
	VppHostTapSpec   *InterfaceSpec        `json:"vppHostTapSpec,omitempty"`
	UplinkInterfaces []UplinkInterfaceSpec `json:"uplinkInterfaces,omitempty"`
}

func (cfg *CalicoVppInterfacesConfigType) Validate() (err error) {
	err = cfg.MaxPodIfSpec.Validate(nil)
	if err != nil {
		return err
	}
	if cfg.DefaultPodIfSpec == nil {
		cfg.DefaultPodIfSpec = &InterfaceSpec{
			NumRxQueues: 1,
			NumTxQueues: 1,
			RxQueueSize: 0,
			TxQueueSize: 0,
		}
	}
	err = cfg.DefaultPodIfSpec.Validate(cfg.MaxPodIfSpec)
	if err != nil {
		return errors.Wrap(err, "default pod interface spec exceeds max interface spec")
	}
	isL3 := cfg.DefaultPodIfSpec.GetIsL3(false)
	cfg.DefaultPodIfSpec.IsL3 = &isL3

	if cfg.VppHostTapSpec == nil {
		cfg.VppHostTapSpec = &InterfaceSpec{
			NumRxQueues: 1,
			NumTxQueues: 1,
			RxQueueSize: 1024,
			TxQueueSize: 1024,
		}
	}
	_ = cfg.VppHostTapSpec.Validate(nil)

	return
}

func (cfg *CalicoVppInterfacesConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

type CalicoVppInitialConfigConfigType struct { //out of agent and vppmanager
	VppStartupSleepSeconds int `json:"vppStartupSleepSeconds"`
	// CorePattern is the pattern to use for VPP corefiles.
	// Usually "/var/lib/vpp/vppcore.%e.%p"
	CorePattern      string `json:"corePattern"`
	ExtraAddrCount   int    `json:"extraAddrCount"`
	IfConfigSavePath string `json:"ifConfigSavePath"`
	// DefaultGWs Comma separated list of IPs to be
	// configured in VPP as default GW
	DefaultGWs string `json:"defaultGWs"`
	// RedirectToHostRules is a list of rules for redirecting
	// traffic to host. This is used for DNS support in kind
	RedirectToHostRules []RedirectToHostRulesConfigType `json:"redirectToHostRules"`
	// PrometheusListenEndpoint is the endpoint on which prometheus will
	// listen and report stats. By default curl http://localhost:8888/metrics
	PrometheusListenEndpoint string `json:"prometheusListenEndpoint"`
	// PrometheusRecordMetricInterval is the interval at which we update the
	// prometheus stats polling VPP stats segment. Default to 5 seconds
	PrometheusRecordMetricInterval *time.Duration `json:"prometheusRecordMetricInterval"`
}

func (cfg *CalicoVppInitialConfigConfigType) Validate() (err error) {
	if cfg.PrometheusListenEndpoint == "" {
		cfg.PrometheusListenEndpoint = ":8888"
	}
	if cfg.PrometheusRecordMetricInterval == nil {
		prometheusRecordMetricInterval := 5 * time.Second
		cfg.PrometheusRecordMetricInterval = &prometheusRecordMetricInterval
	}
	return nil
}
func (cfg *CalicoVppInitialConfigConfigType) GetDefaultGWs() (gws []net.IP, err error) {
	gws = make([]net.IP, 0)
	if cfg.DefaultGWs != "" {
		for _, defaultGWStr := range strings.Split(cfg.DefaultGWs, ",") {
			defaultGW := net.ParseIP(defaultGWStr)
			if defaultGW == nil {
				err = errors.Errorf("Unable to parse IP: %s", defaultGWStr)
				return
			}
			gws = append(gws, defaultGW)
		}
	}
	return
}

func (cfg *CalicoVppInitialConfigConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

// LoadConfig loads the calico-vpp-agent configuration from the environment
func loadConfig(log *logrus.Logger, doLogOutput bool) (err error) {
	errs := ParseAllEnvVars()
	if len(errs) > 0 {
		return fmt.Errorf("environment parsing errors : %s", errs)
	}

	log.SetLevel(*LogLevel)
	if *LogFormat == "pretty" {
		formatter := &logrus.TextFormatter{
			DisableTimestamp: true,
			ForceColors:      true,
		}
		log.SetFormatter(formatter)
		logrus.SetFormatter(formatter)
	}

	if *InitScriptTemplate != "" {
		*HookScriptBeforeIfRead = *InitScriptTemplate
	}

	if doLogOutput {
		PrintAgentConfig(log)

		for _, e := range os.Environ() {
			pair := strings.SplitN(e, "=", 2)
			if strings.Contains(pair[0], "CALICOVPP_") {
				if !isEnvVarSupported(pair[0]) {
					log.Warnf("Environment variable %s is not supported", pair[0])
				}
			}
		}
	}

	return nil
}

func LoadConfig(log *logrus.Logger) (err error) {
	return loadConfig(log, true /*  doLogOutput */)
}

func LoadConfigSilent(log *logrus.Logger) (err error) {
	return loadConfig(log, false /*  doLogOutput */)
}

const (
	DriverUioPciGeneric = "uio_pci_generic"
	DriverVfioPci       = "vfio-pci"
	DriverVirtioPci     = "virtio-pci"
	DriverI40E          = "i40e"
	DriverICE           = "ice"
	DriverMLX5Core      = "mlx5_core"
	DriverVmxNet3       = "vmxnet3"
)

type vppManagerStatus string

const (
	Ready    vppManagerStatus = "ready"
	Starting vppManagerStatus = "starting"
)

type UplinkStatus struct {
	SwIfIndex           uint32
	TapSwIfIndex        uint32
	LinkIndex           int
	Name                string
	IsMain              bool
	Mtu                 int
	PhysicalNetworkName string

	// FakeNextHopIP4 is the computed next hop for v4 routes added
	// in linux to (ServiceCIDR, podCIDR, etc...) towards this interface
	FakeNextHopIP4 net.IP
	// FakeNextHopIP6 is the computed next hop for v6 routes added
	// in linux to (ServiceCIDR, podCIDR, etc...) towards this interface
	FakeNextHopIP6 net.IP
}

type PhysicalNetwork struct {
	VrfID    uint32
	PodVrfID uint32
}

type VppManagerInfo struct {
	Status         vppManagerStatus
	UplinkStatuses map[string]UplinkStatus
	PhysicalNets   map[string]PhysicalNetwork
}

func (i *VppManagerInfo) GetMainSwIfIndex() uint32 {
	for _, u := range i.UplinkStatuses {
		if u.IsMain {
			return u.SwIfIndex
		}
	}
	return vpplink.InvalidSwIfIndex
}

// UnsafeNoIommuMode represents the content of the /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
// file. The 'disabled' value is used when no iommu is available in the environment.
type UnsafeNoIommuMode string

const (
	VfioUnsafeNoIommuModeYES      UnsafeNoIommuMode = "Y"
	VfioUnsafeNoIommuModeNO       UnsafeNoIommuMode = "N"
	VfioUnsafeNoIommuModeDISABLED UnsafeNoIommuMode = "disabled"
)

type VppManagerParams struct {
	UplinksSpecs []UplinkInterfaceSpec
	/* Capabilities */
	LoadedDrivers                      map[string]bool
	KernelVersion                      *KernelVersion
	AvailableHugePages                 int
	InitialVfioEnableUnsafeNoIommuMode UnsafeNoIommuMode

	NodeAnnotations map[string]string
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

type LinuxInterfaceState struct {
	PciID         string
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
		iLen, _ := c.Routes[i].Dst.Mask.Size()
		jLen, _ := c.Routes[j].Dst.Mask.Size()
		return iLen > jLen
	})
}

func getCpusetCPU() (string, error) {
	content, err := os.ReadFile("/sys/fs/cgroup/cpuset.cpus")
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	cpusetCPU := strings.TrimSpace(string(content))

	if len(cpusetCPU) == 0 {
		return "", nil
	}
	return regexp.MustCompile("[,-]").Split(cpusetCPU, 2)[0], nil
}

func TemplateScriptReplace(input string, params *VppManagerParams, conf []*LinuxInterfaceState) (template string, err error) {
	template = input
	if conf != nil {
		/* We might template scripts before reading interface conf */
		template = strings.ReplaceAll(template, "__PCI_DEVICE_ID__", conf[0].PciID)
		for i, ifcConf := range conf {
			template = strings.ReplaceAll(template, "__PCI_DEVICE_ID_"+strconv.Itoa(i)+"__", ifcConf.PciID)
		}
	}
	vppcpu, err := getCpusetCPU()
	if err != nil {
		return "", err
	}
	template = strings.ReplaceAll(template, "__CPUSET_CPUS_FIRST__", vppcpu)
	template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", params.UplinksSpecs[0].InterfaceName)
	for i, ifc := range params.UplinksSpecs {
		template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF_"+fmt.Sprintf("%d", i)+"__", ifc.InterfaceName)
	}
	for key, value := range params.NodeAnnotations {
		template = strings.ReplaceAll(template, fmt.Sprintf("__NODE_ANNOTATION:%s__", key), value)
	}
	return template, nil
}

func PrintAgentConfig(log *logrus.Logger) {
	versionFileStr, err := os.ReadFile(CalicoVppVersionFile)
	if err != nil {
		log.Infof("No version file present %s", CalicoVppVersionFile)
	} else {
		log.Infof("Version info\n%s", versionFileStr)
	}
	PrintEnvVarConfig(log)
}

func DefaultToPtr[T any](ptr *T, defaultV T) *T {
	if ptr == nil {
		return &defaultV
	}
	return ptr
}
