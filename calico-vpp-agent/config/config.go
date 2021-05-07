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
	log "github.com/sirupsen/logrus"
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
	TapGSOEnvVar               = "CALICOVPP_DEBUG_ENABLE_GSO"
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
	BgpLogLevelEnvVar          = "CALICO_BGP_LOGSEVERITYSCREEN"
	LogLevelEnvVar             = "CALICO_LOG_LEVEL"
	ServicePrefixEnvVar        = "SERVICE_PREFIX"
	EnableSRv6EnvVar           = "CALICOVPP_SRV6_ENABLED"

	DefaultVXLANVni      = 4096
	DefaultWireguardPort = 51820

	defaultRxMode = types.Adaptative
)

var (
	TapNumRxQueues           = 1
	TapNumTxQueues           = 1
	TapGSOEnabled            = true
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
	PodMtu                   int = 0
	IpsecNbAsyncCryptoThread int = 0

	felixConfigReceived = false
	felixConfigChan     = make(chan struct{})

	felixIPIPEnabled          = false
	felixIPIPMtu          int = 0
	felixVXLANEnabled         = false
	felixVXLANMtu         int = 0
	felixWireguardEnabled     = false
	felixWireguardMtu     int = 0
)

func PrintAgentConfig(log *logrus.Logger) {
	log.Infof("Config:TapNumRxQueues    %d", TapNumRxQueues)
	log.Infof("Config:TapGSOEnabled     %t", TapGSOEnabled)
	log.Infof("Config:EnableServices    %t", EnableServices)
	log.Infof("Config:EnableIPSec       %t", EnableIPSec)
	log.Infof("Config:CrossIpsecTunnels %t", CrossIpsecTunnels)
	log.Infof("Config:EnablePolicies    %t", EnablePolicies)
	log.Infof("Config:IpsecAddressCount %d", IpsecAddressCount)
	log.Infof("Config:RxMode            %d", TapRxMode)
	log.Infof("Config:BgpLogLevel       %d", BgpLogLevel)
	log.Infof("Config:LogLevel          %d", LogLevel)
	log.Infof("Config:HostMtu           %d", HostMtu)
	log.Infof("Config:PodMtu            %d", PodMtu)
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

	if conf := getEnvValue(BgpLogLevelEnvVar); conf != "" {
		loglevel, err := logrus.ParseLevel(conf)
		if err != nil {
			log.WithError(err).Error("Failed to parse BGP loglevel: %s, defaulting to info", conf)
		} else {
			BgpLogLevel = loglevel
		}
	}

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

	if conf := getEnvValue(TapGSOEnvVar); conf != "" {
		gso, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapGSOEnvVar, conf, gso, err)
		}
		TapGSOEnabled = gso
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

func WaitForFelixConfig() {
	<-felixConfigChan
}

func HandleFelixConfig(config map[string]string) {
	felixIPIPEnabled, _ = strconv.ParseBool(config["IpInIpEnabled"])
	felixIPIPMtu, _ = strconv.Atoi(config["IpInIpMtu"])
	if felixIPIPMtu == 0 {
		felixIPIPMtu = HostMtu - 20
	}
	felixVXLANEnabled, _ = strconv.ParseBool(config["VXLANEnabled"])
	felixVXLANMtu, _ = strconv.Atoi(config["VXLANMTU"])
	if felixVXLANMtu == 0 {
		felixVXLANMtu = HostMtu - 50
	}
	felixWireguardEnabled, _ = strconv.ParseBool(config["WireguardEnabled"])
	felixWireguardMtu, _ = strconv.Atoi(config["WireguardMTU"])
	if felixWireguardMtu == 0 {
		felixWireguardMtu = HostMtu - 60
	}

	// Reproduce felix algorithm in determinePodMTU to determine pod MTU
	// The part where it defaults to the host MTU is done in AddVppInterface
	// TODO: move the code that retrieves the host mtu to this module...
	for _, s := range []struct {
		mtu     int
		enabled bool
	}{
		{felixIPIPMtu, felixIPIPEnabled},
		{felixVXLANMtu, felixVXLANEnabled},
		{felixWireguardMtu, felixWireguardEnabled},
		{HostMtu - 60, EnableIPSec},
	} {
		if s.enabled && s.mtu != 0 && (s.mtu < PodMtu || PodMtu == 0) {
			PodMtu = s.mtu
		}
	}
	if PodMtu == 0 {
		PodMtu = HostMtu
	}
	if PodMtu > HostMtu {
		log.Warnf("Configured MTU (%d) is larger than detected host interface MTU (%d)", PodMtu, HostMtu)
	}
	log.Infof("Determined pod MTU: %d", PodMtu)

	// Note: This function will be called each time the Felix config changes.
	// If we start handling config settings that require agent restart,
	// we'll need to add a mechanism for that

	if !felixConfigReceived {
		felixConfigReceived = true
		felixConfigChan <- struct{}{}
	}
}
