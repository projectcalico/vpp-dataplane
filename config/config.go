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
	"path/filepath"
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
	// CniServerStateFileVersion is the version of the CNI server state file
	// it is used to ensure compatibility when reloading data
	CniServerStateFileVersion = 11
	// MaxAPITagLen is the limit number of character allowed in VPP API tags
	MaxAPITagLen = 63
	// VrfTagHashLen is the number of hash charatecters (b64) of the name
	// to use in the tag prefix of VRFs
	VrfTagHashLen = 8

	MemifPortAnnotation string = "cni.projectcalico.org/vppExtraMemifPorts"
	VclAnnotation       string = "cni.projectcalico.org/vppVcl"
	IfSpecAnnotation    string = "cni.projectcalico.org/vppInterfacesSpec"
	IfSpecPBLAnnotation string = "cni.projectcalico.org/vppExtraMemifSpec"
	SpoofAnnotation     string = "cni.projectcalico.org/AllowedSourcePrefixes"

	KeepOriginalPacketAnnotation string = "cni.projectcalico.org/vppKeepOriginalPacket"
	HashConfigAnnotation         string = "cni.projectcalico.org/vppHashConfig"
	LBTypeAnnotation             string = "cni.projectcalico.org/vppLBType"
)

type BGPServerModeType string

const (
	BGPServerModeDualStack BGPServerModeType = "dualStack"
	BGPServerModeV4Only    BGPServerModeType = "v4Only"
)

var (
	CniServerStateFilename = fmt.Sprintf(
		"/var/run/vpp/calicovpp_state.v%d.json",
		CniServerStateFileVersion,
	)
	// fake constants for place where we need a pointer to true or false
	True  = true
	False = false

	NodeName      = RequiredStringEnvVar("NODENAME")
	LogLevel      = EnvVar("CALICOVPP_LOG_LEVEL", logrus.InfoLevel, logrus.ParseLevel)
	BGPLogLevel   = EnvVar("CALICOVPP_BGP_LOG_LEVEL", apipb.SetLogLevelRequest_INFO, BGPLogLevelParse)
	BGPServerMode = EnvVar("CALICOVPP_BGP_SERVER_MODE", BGPServerModeDualStack, BGPServerModeParse)

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

	/* Template for VppConfigFile (/etc/vpp/startup.conf)
	   It contains the VPP startup configuration */
	ConfigTemplate = RequiredStringEnvVar("CALICOVPP_CONFIG_TEMPLATE")

	/* Template for VppConfigExecFile (/etc/vpp/startup.exec)
	   It contains the CLI to be executed in vppctl after startup */
	ConfigExecTemplate = StringEnvVar("CALICOVPP_CONFIG_EXEC_TEMPLATE", "")

	// Default hook script embedded at compile time for backward compatibility.
	// This is the legacy bash script used when CALICOVPP_ENABLE_NETWORK_MANAGER_HOOK=false
	//go:embed default_hook.sh
	DefaultHookScript string

	/* Enable/disable the native Go NetworkManagerHook implementation.
	 * - true (default):  Native Go hooks execute (unless overridden by user scripts below)
	 * - false:           Fallback to embedded default_hook.sh (legacy bash behavior) */
	EnableNetworkManagerHook = BoolEnvVar("CALICOVPP_ENABLE_NETWORK_MANAGER_HOOK", true)

	/* Hook scripts that override native Go hooks when configured.
	 * When a user script is provided for any hook point, it takes highest priority:
	 * - The user script executes instead of the native Go hook
	 * - Leaving empty ("") allows native Go hooks to run (when flag=true)
	 * - When flag=false and empty, uses embedded default_hook.sh as fallback */

	/* Run this before getLinuxConfig() in case this is a script
	 * that's responsible for creating the interface.
	 * Also captures host udev ID_NET_NAME_* properties before driver unbind. */
	HookScriptBeforeIfRead = StringEnvVar("CALICOVPP_HOOK_BEFORE_IF_READ", "")
	/* Bash script template run just after getting config
	   from $CALICOVPP_INTERFACE & before starting VPP */
	HookScriptBeforeVppRun = StringEnvVar("CALICOVPP_HOOK_BEFORE_VPP_RUN", "")
	/* Bash script template run after VPP has started */
	HookScriptVppRunning = StringEnvVar("CALICOVPP_HOOK_VPP_RUNNING", "")
	/* Bash script template run when VPP stops gracefully */
	HookScriptVppDoneOk = StringEnvVar("CALICOVPP_HOOK_VPP_DONE_OK", "")
	/* Bash script template run when VPP stops with an error */
	HookScriptVppErrored = StringEnvVar("CALICOVPP_HOOK_VPP_ERRORED", "")

	Info = &VppManagerInfo{
		UplinkStatuses: make(map[string]UplinkStatus),
		PhysicalNets:   make(map[string]PhysicalNetwork),
	}

	// VppsideTap0Address is the IP address we add to the tap0
	// so that it can receive ipv4 packets
	VppsideTap0Address = PrefixEnvVar(
		"CALICOVPP_TAP0_ADDR",
		MustParseCIDR("169.254.0.1/32"),
	)
)

/* RunHook() executes a bash script at a specific hook point.
 * Used for both user-provided scripts and the embedded default_hook.sh fallback. */
func RunHook(hookScript *string, hookName string, params *VppManagerParams, log *logrus.Logger) {
	if *hookScript == "" {
		return
	}
	template, err := TemplateScriptReplace(*hookScript, params, nil)
	if err != nil {
		log.Warnf("Running hook %s errored with %s", hookName, err)
		return
	}

	cmd := exec.Command("/bin/bash", "-c", template, hookName, params.UplinksSpecs[0].InterfaceName)
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
	IP   net.IP `json:"ip,omitempty"`
	/* "tcp", "udp",... */
	Proto types.IPProto `json:"proto,omitempty"`
}

type CalicoVppDebugConfigType struct {
	ServicesEnabled         *bool `json:"servicesEnabled,omitempty"`
	GSOEnabled              *bool `json:"gsoEnabled,omitempty"`
	SpreadTxQueuesOnWorkers *bool `json:"spreadTxQueuesOnWorkers,omitempty"`
	EnableUdevNetNameRules  *bool `json:"enableUdevNetNameRules,omitempty"`
	// FetchV6LLntries is the number of times (one try per second) we try to
	// get the v6 link local address from the tap created in linux
	// to replace the uplink before giving up.
	FetchV6LLntries *uint32 `json:"fetchV6LLntries,omitempty"`
	// TranslateUplinkAddrMaskTo64 if set will convert all the non link local
	// addresses read on the uplink interface that are [::ipv6]/128 to be [::ipv6]/64
	// this is enabled by default as VPP currently lacks the implementation of
	// getting the prefix over router advertisements with option L and !A
	// proper implementation will come in a later VPP patch.
	TranslateUplinkAddrMaskTo64 *bool `json:"translateUplinkAddrMaskTo64,omitempty"`
}

func (cfg *CalicoVppDebugConfigType) String() string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func (cfg *CalicoVppDebugConfigType) Validate() (err error) {
	if cfg.ServicesEnabled == nil {
		cfg.ServicesEnabled = &True
	}
	if cfg.GSOEnabled == nil {
		cfg.GSOEnabled = &True
	}
	if cfg.SpreadTxQueuesOnWorkers == nil {
		cfg.SpreadTxQueuesOnWorkers = &False
	}
	if cfg.EnableUdevNetNameRules == nil {
		cfg.EnableUdevNetNameRules = &True
	}
	if cfg.TranslateUplinkAddrMaskTo64 == nil {
		cfg.TranslateUplinkAddrMaskTo64 = &True
	}
	var v uint32 = 5
	if cfg.FetchV6LLntries == nil {
		cfg.FetchV6LLntries = &v
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
	// IP4NeighborsMaxNumber is the maximum number of allowed IPv4 neighbors
	// VPP allows. Defaults to 50k
	IP4NeighborsMaxNumber *uint32 `json:"ip4NeighborsMaxNumber"`
	// IP6NeighborsMaxNumber is the maximum number of allowed IPv4 neighbors
	// VPP allows. Defaults to 50k
	IP6NeighborsMaxNumber *uint32 `json:"ip6NeighborsMaxNumber"`
	// IP4NeighborsMaxAge is the maximum age of IPv4 neighbors in seconds
	// ARPs will be issued after said interval. Be aware ARPs in VPP are
	// issued using a pre-existing vlib buffer hence dropping a packet
	// defaults to 30 seconds. Use 0 to disable.
	IP4NeighborsMaxAge *uint32 `json:"ip4NeighborsMaxAge"`
	// IP6NeighborsMaxAge is the maximum age of IPv4 neighbors in seconds
	// ARPs will be issued after said interval. Be aware ARPs in VPP are
	// issued using a pre-existing vlib buffer hence dropping a packet
	// defaults to 30 seconds. Use 0 to disable.
	IP6NeighborsMaxAge *uint32 `json:"ip6NeighborsMaxAge"`
	// PrometheusStatsPrefix is the prefix to use for Prometheus metrics
	// Defaults to "cni.projectcalico.vpp."
	PrometheusStatsPrefix string `json:"prometheusStatsPrefix"`
	// HealthCheckPort is the port on which the health check HTTP server listens
	// Defaults to 9090
	HealthCheckPort *uint32 `json:"healthCheckPort"`
}

func (cfg *CalicoVppInitialConfigConfigType) Validate() (err error) {
	if cfg.PrometheusListenEndpoint == "" {
		cfg.PrometheusListenEndpoint = ":8888"
	}
	if cfg.PrometheusRecordMetricInterval == nil {
		prometheusRecordMetricInterval := 5 * time.Second
		cfg.PrometheusRecordMetricInterval = &prometheusRecordMetricInterval
	}
	cfg.IP4NeighborsMaxNumber = DefaultToPtr(
		cfg.IP4NeighborsMaxNumber, 50000,
	)
	cfg.IP6NeighborsMaxNumber = DefaultToPtr(
		cfg.IP6NeighborsMaxNumber, 50000,
	)
	cfg.IP4NeighborsMaxAge = DefaultToPtr(
		cfg.IP4NeighborsMaxAge, 30,
	)
	cfg.IP6NeighborsMaxAge = DefaultToPtr(
		cfg.IP6NeighborsMaxAge, 30,
	)
	if cfg.PrometheusStatsPrefix == "" {
		cfg.PrometheusStatsPrefix = "cni.projectcalico.vpp."
	}
	cfg.HealthCheckPort = DefaultToPtr(
		cfg.HealthCheckPort, 9090,
	)
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

	UplinkAddresses []*net.IPNet
}

func (uplinkStatus *UplinkStatus) GetAddress(ipFamily vpplink.IPFamily) *net.IPNet {
	for _, addr := range uplinkStatus.UplinkAddresses {
		if vpplink.IPFamilyFromIPNet(addr) == ipFamily {
			return addr
		}
	}
	return nil
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
	PciID  string
	Driver string
	IsUp   bool
	// addresses is the list of addresses present
	// on the netlink interface when the CNI starts up
	// keep in mind that addresses will contain the ipv6
	// link local of the old phy. Which might be different
	// from IPv6LinkLocal
	addresses []netlink.Addr
	// IPv6LinkLocal is the ipv6 link local address that the
	// system assigns to the tap interface replacing the phy
	// when VPP starts
	IPv6LinkLocal netlink.Addr
	// routes is the list of routes present on the netlink
	// interface when the CNI starts up
	routes        []netlink.Route
	Neighbors     []netlink.Neigh
	HardwareAddr  net.HardwareAddr
	PromiscOn     bool
	NumTxQueues   int
	NumRxQueues   int
	DoSwapDriver  bool
	Mtu           int
	InterfaceName string
	IsTunTap      bool
	IsVeth        bool
	// TapSwIfIndex is the sw_if_index of the tap interface
	// created in VPP for this interface
	TapSwIfIndex uint32
}

func bindPCIDevicesToKernel() error {
	drivers := []string{"igb_uio", "uio_pci_generic", "vfio-pci"}
	removed := false

	for _, driver := range drivers {
		pattern := filepath.Join("/sys/bus/pci/drivers", driver, "*")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}

		for _, f := range matches {
			configPath := filepath.Join(f, "config")

			// Skip if config does not exist
			if _, err := os.Stat(configPath); err != nil {
				continue
			}

			// Check if config file is in use via fuser
			cmd := exec.Command("fuser", "-s", configPath)
			if err := cmd.Run(); err == nil {
				// fuser found a user, skip
				continue
			}

			// Write "1" to remove file
			removePath := filepath.Join(f, "remove")
			if err := os.WriteFile(removePath, []byte("1"), 0200); err != nil {
				return err
			}

			removed = true
		}
	}

	// If any device was removed, rescan PCI bus
	if removed {
		if err := os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0200); err != nil {
			return err
		}
	}

	return nil
}

func LoadInterfaceConfigFromLinux(interfaceName string) (*LinuxInterfaceState, error) {
	conf := LinuxInterfaceState{
		TapSwIfIndex: ^uint32(0), // in case we forget to set it
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// attempt binding PCI devices to kernel
		bindErr := bindPCIDevicesToKernel()
		if bindErr != nil {
			return nil, errors.Wrapf(err, "cannot find interface named %s, cannot bind pci devices to kernel: %v", interfaceName, bindErr)
		}
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot find interface named %s after binding devices to kernel", interfaceName)
		}
	}
	conf.IsUp = (link.Attrs().Flags & net.FlagUp) != 0
	if conf.IsUp {
		// Grab addresses and routes
		conf.addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s addresses", interfaceName)
		}

		conf.routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s routes", interfaceName)
		}
		conf.sortRoutes()
	}
	conf.HardwareAddr = link.Attrs().HardwareAddr
	if !conf.HasNodeIP4() && !conf.HasNodeIP6() {
		return nil, errors.Errorf("no address found for node")
	}

	conf.DoSwapDriver = false
	conf.PromiscOn = link.Attrs().Promisc == 1
	conf.NumTxQueues = link.Attrs().NumTxQueues
	conf.NumRxQueues = link.Attrs().NumRxQueues
	conf.Mtu = link.Attrs().MTU
	_, conf.IsTunTap = link.(*netlink.Tuntap)
	_, conf.IsVeth = link.(*netlink.Veth)
	conf.InterfaceName = interfaceName

	return &conf, nil
}

func (c *LinuxInterfaceState) AddressString() string {
	var str []string
	for _, addr := range c.addresses {
		str = append(str, addr.String())
	}
	return strings.Join(str, ",")
}

func (c *LinuxInterfaceState) HasNodeIP6() bool {
	return c.getNodeIP(true /* isIP6 */) != nil
}

func (c *LinuxInterfaceState) HasNodeIP4() bool {
	return c.getNodeIP(false /* isIP6 */) != nil
}

func (c *LinuxInterfaceState) GetAddresses() []netlink.Addr {
	ret := make([]netlink.Addr, 0)
	for _, addr := range c.addresses {
		if addr.IP.IsLinkLocalUnicast() && isV6Cidr(addr.IPNet) {
			continue
		}
		ret = append(ret, addr)
	}
	return ret
}

func (c *LinuxInterfaceState) GetRoutes() []netlink.Route {
	ret := make([]netlink.Route, 0)
	for _, route := range c.routes {
		if route.Dst != nil && route.Dst.IP.IsLinkLocalUnicast() && isV6Cidr(route.Dst) {
			continue
		}
		ret = append(ret, route)
	}
	return ret
}

func (c *LinuxInterfaceState) getNodeIP(isIP6 bool) *net.IPNet {
	for _, addr := range c.GetAddresses() {
		if vpplink.IsIP6(addr.IP) == isIP6 {
			return addr.IPNet
		}
	}
	return nil
}

func (c *LinuxInterfaceState) GetNodeIP6() string {
	if i := c.getNodeIP(true /* isIP6 */); i != nil {
		return i.String()
	}
	return ""
}

func (c *LinuxInterfaceState) GetNodeIP4() string {
	if i := c.getNodeIP(false /* isIP6 */); i != nil {
		return i.String()
	}
	return ""
}

func (c *LinuxInterfaceState) GetAddressesAsIPNet() []*net.IPNet {
	ret := make([]*net.IPNet, 0)
	for _, addr := range c.addresses {
		ret = append(ret, addr.IPNet)
	}
	return ret
}

func (c *LinuxInterfaceState) HasAddr(addr net.IP) bool {
	for _, a := range c.addresses {
		if addr.Equal(a.IP) {
			return true
		}
	}
	return false
}

func (c *LinuxInterfaceState) RouteString() string {
	var str []string
	for _, route := range c.GetRoutes() {
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

// sortRoutes sorts the route slice by dependency order, so we can then add them
// in the order of the slice without issues
func (c *LinuxInterfaceState) sortRoutes() {
	sort.SliceStable(c.routes, func(i, j int) bool {
		// Directly connected routes go first
		if c.routes[i].Gw == nil {
			return true
		} else if c.routes[j].Gw == nil {
			return false
		}
		// Default routes go last
		if c.routes[i].Dst == nil {
			return false
		} else if c.routes[j].Dst == nil {
			return true
		}
		// Finally sort by decreasing prefix length
		iLen, _ := c.routes[i].Dst.Mask.Size()
		jLen, _ := c.routes[j].Dst.Mask.Size()
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

func isV6Cidr(cidr *net.IPNet) bool {
	_, bits := cidr.Mask.Size()
	return bits == 128
}
