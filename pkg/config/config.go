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
	"strings"
	"time"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
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

	DefaultVRFIndex = uint32(0)
	PuntTableID     = uint32(1)
	PodVRFIndex     = uint32(2)
)

var (
	CniServerStateFilename = fmt.Sprintf(
		"/var/run/vpp/calicovpp_state.v%d.json",
		CniServerStateFileVersion,
	)
	// fake constants for place where we need a pointer to true or false
	True  = true
	False = false

	// maxCoreFiles sets the maximum number of corefiles to keep and deletes older ones
	DefaultMaxCoreFiles = 2

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
	VppStatsSocket                   = StringEnvVar("CALICOVPP_STATS_SOCKET", "")

	/* Deprecated vars */
	/* linux name of the uplink interface to be used by VPP */
	InterfaceVar = StringEnvVar("CALICOVPP_INTERFACE", "")
	/* Driver to consume the uplink with. Leave empty for autoconf */
	NativeDriverEnvVar = StringEnvVar("CALICOVPP_NATIVE_DRIVER", "")
	SwapDriverEnvVar   = StringEnvVar("CALICOVPP_SWAP_DRIVER", "")

	/* Template for VppConfigFile (/etc/vpp/startup.conf)
	   It contains the VPP startup configuration */
	ConfigTemplateEnvVar = RequiredStringEnvVar("CALICOVPP_CONFIG_TEMPLATE")

	/* Template for VppConfigExecFile (/etc/vpp/startup.exec)
	   It contains the CLI to be executed in vppctl after startup */
	ConfigExecTemplateEnvVar = StringEnvVar("CALICOVPP_CONFIG_EXEC_TEMPLATE", "")

	/* Enable/disable the native Go NetworkManagerHook implementation.
	 * - true (default):  Native Go hooks execute (unless overridden by user scripts below)
	 * - false:           Hooks are no-ops unless a user-provided HookScript* is set */
	EnableNetworkManagerHook = BoolEnvVar("CALICOVPP_ENABLE_NETWORK_MANAGER_HOOK", true)

	/* Hook scripts that override native Go hooks when configured.
	 * When a user script is provided for any hook point, it takes highest priority:
	 * - The user script executes instead of the native Go hook
	 * - Leaving empty ("") allows native Go hooks to run (when flag=true)
	 * - When flag=false and empty, the hook is a no-op */

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

	// VppsideTap0Address is the IP address we add to the tap0
	// so that it can receive ipv4 packets
	VppsideTap0Address = PrefixEnvVar(
		"CALICOVPP_TAP0_ADDR",
		MustParseCIDR("169.254.0.1/32"),
	)
)

func GetCalicoVppDebug() *CalicoVppDebugConfigType                 { return *CalicoVppDebug }
func GetCalicoVppInterfaces() *CalicoVppInterfacesConfigType       { return *CalicoVppInterfaces }
func GetCalicoVppFeatureGates() *CalicoVppFeatureGatesConfigType   { return *CalicoVppFeatureGates }
func GetCalicoVppIpsec() *CalicoVppIpsecConfigType                 { return *CalicoVppIpsec }
func GetCalicoVppSrv6() *CalicoVppSrv6ConfigType                   { return *CalicoVppSrv6 }
func GetCalicoVppInitialConfig() *CalicoVppInitialConfigConfigType { return *CalicoVppInitialConfig }

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
	CorePattern string `json:"corePattern"`
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
