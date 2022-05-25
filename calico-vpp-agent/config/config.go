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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

const (
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	CNIServerSocket        = "/var/run/calico/cni-server.sock"
	FelixDataplaneSocket   = "/var/run/calico/felix-dataplane.sock"
	VppAPISocket           = "/var/run/vpp/vpp-api.sock"
	VppManagerStatusFile   = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile   = "/var/run/vpp/vppmanagertap0"
	VppManagerLinuxMtu     = "/var/run/vpp/vppmanagerlinuxmtu"
	CalicoVppPidFile       = "/var/run/vpp/calico_vpp.pid"
	CniServerStateFile     = "/var/run/vpp/calico_vpp_pod_state"

	NodeNameEnvVar             = "NODENAME"
	TapNumRxQueuesEnvVar       = "CALICOVPP_TAP_RX_QUEUES"
	TapNumTxQueuesEnvVar       = "CALICOVPP_TAP_TX_QUEUES"
	MemifEnabledEnvVar         = "CALICOVPP_ENABLE_MEMIF"
	VCLEnabledEnvVar           = "CALICOVPP_ENABLE_VCL"
	MultinetEnabledEnvVar      = "CALICOVPP_ENABLE_MULTINET"
	PodGSOEnabledEnvVar        = "CALICOVPP_DEBUG_ENABLE_GSO"
	EnableServicesEnvVar       = "CALICOVPP_DEBUG_ENABLE_NAT"
	EnableMaglevEnvVar         = "CALICOVPP_DEBUG_ENABLE_MAGLEV"
	EnablePoliciesEnvVar       = "CALICOVPP_DEBUG_ENABLE_POLICIES"
	CrossIpsecTunnelsEnvVar    = "CALICOVPP_IPSEC_CROSS_TUNNELS"
	EnableIPSecEnvVar          = "CALICOVPP_IPSEC_ENABLED"
	IPSecExtraAddressesEnvVar  = "CALICOVPP_IPSEC_ASSUME_EXTRA_ADDRESSES"
	IPSecIkev2PskEnvVar        = "CALICOVPP_IPSEC_IKEV2_PSK"
	TapRxModeEnvVar            = "CALICOVPP_TAP_RX_MODE"
	TapQueueSizeEnvVar         = "CALICOVPP_TAP_RING_SIZE"
	IpsecNbAsyncCryptoThEnvVar = "CALICOVPP_IPSEC_NB_ASYNC_CRYPTO_THREAD"
	LogLevelEnvVar             = "CALICO_LOG_LEVEL"
	ServicePrefixEnvVar        = "SERVICE_PREFIX"
	EnableSRv6EnvVar           = "CALICOVPP_SRV6_ENABLED"
	SRv6LocalsidPoolEnvVar     = "CALICOVPP_SR_LS_POOL"
	SRv6PolicyPoolEnvVar       = "CALICOVPP_SR_POLICY_POOL"

	MemifSocketName      = "@vpp/memif"
	DefaultVXLANVni      = 4096
	DefaultVXLANPort     = 4789
	DefaultWireguardPort = 51820

	defaultRxMode = types.Adaptative
)

var (
	TapNumRxQueues = 1
	TapNumTxQueues = 1
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
	TapRxMode                = defaultRxMode
	BgpLogLevel              = logrus.InfoLevel
	LogLevel                 = logrus.InfoLevel
	NodeName                 = ""
	ServiceCIDRs             []*net.IPNet
	TapRxQueueSize           int = 0
	TapTxQueueSize           int = 0
	HostMtu                  int = 0
	IpsecNbAsyncCryptoThread int = 0
	SRv6policyIPPool             = ""
	SRv6localSidIPPool           = ""

	FailsafeInboundHostPorts  string = ""
	FailsafeOutboundHostPorts string = ""
	EndpointToHostAction      string = ""

	ContainerSideMacAddress, _ = net.ParseMAC("02:00:00:00:00:01")
)

func PrintAgentConfig(log *logrus.Logger) {
	log.Infof("Config:TapNumRxQueues    %d", TapNumRxQueues)
	log.Infof("Config:MultinetEnabled   %t", MultinetEnabled)
	log.Infof("Config:MemifEnabled      %t", MemifEnabled)
	log.Infof("Config:VCLEnabled        %t", VCLEnabled)
	log.Infof("Config:PodGSOEnabled     %t", PodGSOEnabled)
	log.Infof("Config:EnableServices    %t", EnableServices)
	log.Infof("Config:EnableIPSec       %t", EnableIPSec)
	log.Infof("Config:CrossIpsecTunnels %t", CrossIpsecTunnels)
	log.Infof("Config:EnablePolicies    %t", EnablePolicies)
	log.Infof("Config:IpsecAddressCount %d", IpsecAddressCount)
	log.Infof("Config:RxMode            %d", TapRxMode)
	log.Infof("Config:LogLevel          %d", LogLevel)
	log.Infof("Config:HostMtu           %d", HostMtu)
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

func fetchHostMtu() (mtu int, err error) {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(VppManagerLinuxMtu)
		if err == nil {
			idx, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 32)
			if err == nil && idx != -1 {
				return int(idx), nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return 0, errors.Errorf("Vpp-host mtu not ready after 20 tries")
}

// LoadConfig loads the calico-vpp-agent configuration from the environment
func LoadConfig(log *logrus.Logger) (err error) {
	supportedEnvVars = make(map[string]bool)

	if conf := getEnvValue(LogLevelEnvVar); conf != "" {
		loglevel, err := logrus.ParseLevel(conf)
		if err != nil {
			log.WithError(err).Error("Failed to parse loglevel: %s, defaulting to info", conf)
		} else {
			LogLevel = loglevel
		}
	}

	NodeName = getEnvValue(NodeNameEnvVar)

	if conf := getEnvValue(TapNumRxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", TapNumRxQueuesEnvVar, conf, queues, err)
		}
		TapNumRxQueues = int(queues)
	}

	if conf := getEnvValue(TapNumTxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", TapNumTxQueuesEnvVar, conf, queues, err)
		}
		TapNumTxQueues = int(queues)
	}

	if conf := getEnvValue(VCLEnabledEnvVar); conf != "" {
		enabled, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", VCLEnabledEnvVar, conf, enabled, err)
		}
		VCLEnabled = enabled
	}

	if conf := getEnvValue(MemifEnabledEnvVar); conf != "" {
		enabled, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", MemifEnabledEnvVar, conf, enabled, err)
		}
		MemifEnabled = enabled
	}

	if conf := getEnvValue(MultinetEnabledEnvVar); conf != "" {
		enabled, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", MultinetEnabledEnvVar, conf, enabled, err)
		}
		MultinetEnabled = enabled
	}

	if conf := getEnvValue(PodGSOEnabledEnvVar); conf != "" {
		gso, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", PodGSOEnabledEnvVar, conf, gso, err)
		}
		PodGSOEnabled = gso
	}

	if conf := getEnvValue(EnableIPSecEnvVar); conf != "" {
		enableIPSec, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnableIPSecEnvVar, conf, enableIPSec, err)
		}
		EnableIPSec = enableIPSec
	}

	if conf := getEnvValue(CrossIpsecTunnelsEnvVar); conf != "" {
		crossIpsecTunnels, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", CrossIpsecTunnelsEnvVar, conf, crossIpsecTunnels, err)
		}
		CrossIpsecTunnels = crossIpsecTunnels
	}

	if conf := getEnvValue(EnableServicesEnvVar); conf != "" {
		enableServices, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnableServicesEnvVar, conf, enableServices, err)
		}
		EnableServices = enableServices
	}

	if conf := getEnvValue(EnableMaglevEnvVar); conf != "" {
		enableMaglev, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnableMaglevEnvVar, conf, enableMaglev, err)
		}
		EnableMaglev = enableMaglev
	}

	if conf := getEnvValue(EnablePoliciesEnvVar); conf != "" {
		enablePolicies, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnablePoliciesEnvVar, conf, enablePolicies, err)
		}
		EnablePolicies = enablePolicies
	}

	if conf := getEnvValue(IPSecExtraAddressesEnvVar); conf != "" {
		extraAddressCount, err := strconv.ParseInt(conf, 10, 8)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", IPSecExtraAddressesEnvVar, conf, extraAddressCount, err)
		}
		IpsecAddressCount = int(extraAddressCount) + 1
	}

	if conf := getEnvValue(IpsecNbAsyncCryptoThEnvVar); conf != "" {
		ipsecNbAsyncCryptoThread, err := strconv.ParseInt(conf, 10, 32)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", IpsecNbAsyncCryptoThEnvVar, conf, ipsecNbAsyncCryptoThread, err)
		}
		IpsecNbAsyncCryptoThread = int(ipsecNbAsyncCryptoThread)
	}

	if conf := getEnvValue(TapQueueSizeEnvVar); conf != "" {
		sizes := strings.Split(conf, ",")
		if len(sizes) == 1 {
			sz, err := strconv.ParseInt(sizes[0], 10, 32)
			if err != nil {
				return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapQueueSizeEnvVar, conf, sz, err)
			}
			TapRxQueueSize = int(sz)
			TapTxQueueSize = int(sz)
		} else if len(sizes) == 2 {
			sz, err := strconv.ParseInt(sizes[0], 10, 32)
			if err != nil {
				return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapQueueSizeEnvVar, conf, sz, err)
			}
			TapRxQueueSize = int(sz)
			sz, err = strconv.ParseInt(sizes[1], 10, 32)
			if err != nil {
				return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapQueueSizeEnvVar, conf, sz, err)
			}
			TapTxQueueSize = int(sz)
		} else {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapQueueSizeEnvVar, conf, sizes, err)
		}
	}

	if conf := getEnvValue(EnableSRv6EnvVar); conf != "" {
		enableSRv6, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnableSRv6EnvVar, conf, enableSRv6, err)
		}
		EnableSRv6 = enableSRv6
	}

	if conf := getEnvValue(SRv6PolicyPoolEnvVar); conf != "" {
		SRv6policyIPPool = conf
	}

	if conf := getEnvValue(SRv6LocalsidPoolEnvVar); conf != "" {
		SRv6localSidIPPool = conf
	}

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

	switch getEnvValue(TapRxModeEnvVar) {
	case "interrupt":
		TapRxMode = types.Interrupt
	case "polling":
		TapRxMode = types.Polling
	case "adaptive":
		TapRxMode = types.Adaptative
	default:
		TapRxMode = defaultRxMode
	}

	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.Contains(pair[0], "CALICOVPP_") {
			if !isEnvVarSupported(pair[0]) {
				log.Warnf("Environment variable %s is not supported", pair[0])
			}
		}
	}

	HostMtu, err = fetchHostMtu()
	if err != nil {
		return err
	}

	return nil
}
