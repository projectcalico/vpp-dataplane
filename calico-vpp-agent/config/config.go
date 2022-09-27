// Copyright (C) 2019 Cisco Systems Inc.
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

	"github.com/pkg/errors"
	common_config "github.com/projectcalico/vpp-dataplane/common-config"
	"github.com/sirupsen/logrus"
)

const (
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	CNIServerSocket        = "/var/run/calico/cni-server.sock"
	FelixDataplaneSocket   = "/var/run/calico/felix-dataplane.sock"
	VppAPISocket           = "/var/run/vpp/vpp-api.sock"
	VppManagerInfoFile     = "/var/run/vpp/vppmanagerinfofile"
	CalicoVppPidFile       = "/var/run/vpp/calico_vpp.pid"
	CniServerStateFile     = "/var/run/vpp/calico_vpp_pod_state"

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
	UserSpecifiedMtu         int = 0
	IpsecNbAsyncCryptoThread int = 0
	SRv6policyIPPool             = ""
	SRv6localSidIPPool           = ""

	DefaultInterfaceSpec common_config.InterfaceSpec = common_config.InterfaceSpec{NumRxQueues: 1, NumTxQueues: 1, RxQueueSize: 0, TxQueueSize: 0}
	MaxIfSpec common_config.InterfaceSpec
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

	var calicoVppInterfaces common_config.CalicoVppInterfaces
	conf := getEnvValue(CalicoVppInterfacesEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppInterfaces)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppInterfacesEnvVar, conf, err)
		}
	}

	var calicoVppFeatureGates common_config.CalicoVppFeatureGates
	conf = getEnvValue(CalicoVppFeatureGatesEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppFeatureGates)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppFeatureGatesEnvVar, conf, err)
		}
	}

	var calicoVppIpsec common_config.CalicoVppIpsec
	conf = getEnvValue(CalicoVppIpsecEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppIpsec)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppIpsecEnvVar, conf, err)
		}
	}

	var calicoVppDebug common_config.CalicoVppDebug
	conf = getEnvValue(CalicoVppDebugEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppDebug)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppDebugEnvVar, conf, err)
		}
	}

	var calicoVppSrv6 common_config.CalicoVppSrv6
	conf = getEnvValue(CalicoVppSrv6EnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppSrv6)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppSrv6EnvVar, conf, err)
		}
	}

	if calicoVppInterfaces.MaxIfSpec != nil {
		MaxIfSpec = *calicoVppInterfaces.MaxIfSpec
	}
	if calicoVppInterfaces.DefaultPodIfSpec != nil {
		if common_config.NotExceedMax(*calicoVppInterfaces.DefaultPodIfSpec, MaxIfSpec) {
			DefaultInterfaceSpec = *calicoVppInterfaces.DefaultPodIfSpec
		} else {
			DefaultInterfaceSpec = MaxIfSpec
		}
	}
	if calicoVppFeatureGates.VCLEnabled != nil {
		VCLEnabled = *calicoVppFeatureGates.VCLEnabled
	}
	if calicoVppFeatureGates.MemifEnabled != nil {
		MemifEnabled = *calicoVppFeatureGates.MemifEnabled
	}
	if calicoVppFeatureGates.MultinetEnabled != nil {
		MultinetEnabled = *calicoVppFeatureGates.MultinetEnabled
	}
	if calicoVppDebug.GSOEnabled != nil {
		PodGSOEnabled = *calicoVppDebug.GSOEnabled
	}
	if calicoVppFeatureGates.IPSecEnabled != nil {
		EnableIPSec = *calicoVppFeatureGates.IPSecEnabled
	}
	if calicoVppDebug.ServicesEnabled != nil {
		EnableServices = *calicoVppDebug.ServicesEnabled
	}
	if calicoVppDebug.MaglevEnabled != nil {
		EnableMaglev = *calicoVppDebug.MaglevEnabled
	}
	if calicoVppDebug.PoliciesEnabled != nil {
		EnablePolicies = *calicoVppDebug.PoliciesEnabled
	}
	if calicoVppIpsec.CrossIpsecTunnels != nil {
		CrossIpsecTunnels = *calicoVppIpsec.CrossIpsecTunnels
	}
	if calicoVppFeatureGates.SRv6Enabled != nil {
		EnableSRv6 = *calicoVppFeatureGates.SRv6Enabled
	}
	SRv6localSidIPPool = calicoVppSrv6.LocalsidPool
	SRv6policyIPPool = calicoVppSrv6.PolicyPool
	IpsecNbAsyncCryptoThread = calicoVppIpsec.NbAsyncCryptoThreads
	extraAddressCount := calicoVppIpsec.ExtraAddresses
	IpsecAddressCount = int(extraAddressCount) + 1
	UserSpecifiedMtu = calicoVppInterfaces.Mtu

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

	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.Contains(pair[0], "CALICOVPP_") {
			if !isEnvVarSupported(pair[0]) {
				log.Warnf("Environment variable %s is not supported", pair[0])
			}
		}
	}

	return nil
}
