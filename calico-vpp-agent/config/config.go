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
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

const (
	DataInterfaceSwIfIndex    = uint32(1) // Assumption: the VPP config ensures this is true
	CNIServerSocket           = "/var/run/calico/cni-server.sock"
	VppAPISocket              = "/var/run/vpp/vpp-api.sock"
	CNIInfoStoreSocket        = "/var/run/calico/cni-infostore.sock"
	VppManagerStatusFile      = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile      = "/var/run/vpp/vppmanagertap0"
	CalicoVppPidFile          = "/var/run/vpp/calico_vpp.pid"
	CniServerStateTempFile    = "/var/run/vpp/calico_vpp_pod_state~"
	CniServerStateFile        = "/var/run/vpp/calico_vpp_pod_state"
	CniServerStateFileVersion = 1 // Used to ensure compatibility wen we reload data

	NodeNameEnvVar            = "NODENAME"
	TapNumRxQueuesEnvVar      = "CALICOVPP_TAP_RX_QUEUES"
	InfoStoreVar              = "CALICOVPP_INFOSTORE_ENABLE"
	TapNumTxQueuesEnvVar      = "CALICOVPP_TAP_TX_QUEUES"
	TapGSOEnvVar              = "CALICOVPP_TAP_GSO_ENABLED"
	EnableServicesEnvVar      = "CALICOVPP_NAT_ENABLED"
	CrossIpsecTunnelsEnvVar   = "CALICOVPP_IPSEC_CROSS_TUNNELS"
	EnableIPSecEnvVar         = "CALICOVPP_IPSEC_ENABLED"
	IPSecExtraAddressesEnvVar = "CALICOVPP_IPSEC_ASSUME_EXTRA_ADDRESSES"
	IPSecIkev2PskEnvVar       = "CALICOVPP_IPSEC_IKEV2_PSK"
	TapRxModeEnvVar           = "CALICOVPP_TAP_RX_MODE"
	TapQueueSizeEnvVar        = "CALICOVPP_TAP_RING_SIZE"
	BgpLogLevelEnvVar         = "CALICO_BGP_LOGSEVERITYSCREEN"
	LogLevelEnvVar            = "CALICO_LOG_LEVEL"
	ServicePrefixEnvVar       = "SERVICE_PREFIX"
	DefaultVXLANVni           = 4096

	defaultRxMode = types.Adaptative
)

var (
	TapNumRxQueues    = 1
	TapNumTxQueues    = 1
	TapGSOEnabled     = false
	EnableServices    = true
	EnableIPSec       = false
	IpsecAddressCount = 1
	CrossIpsecTunnels = false
	IPSecIkev2Psk     = ""
	TapRxMode         = defaultRxMode
	BgpLogLevel       = logrus.InfoLevel
	LogLevel          = logrus.InfoLevel
	NodeName          = ""
	ServiceCIDRs      []*net.IPNet
	TapRxQueueSize    int = 0
	TapTxQueueSize    int = 0
	InfoStoreEnable       = true
)

// LoadConfig loads the calico-vpp-agent configuration from the environment
func LoadConfig(log *logrus.Logger) (err error) {
	if conf := os.Getenv(BgpLogLevelEnvVar); conf != "" {
		loglevel, err := logrus.ParseLevel(conf)
		if err != nil {
			log.WithError(err).Error("Failed to parse BGP loglevel: %s, defaulting to info", conf)
		} else {
			BgpLogLevel = loglevel
		}
	}

	if conf := os.Getenv(LogLevelEnvVar); conf != "" {
		loglevel, err := logrus.ParseLevel(conf)
		if err != nil {
			log.WithError(err).Error("Failed to parse loglevel: %s, defaulting to info", conf)
		} else {
			LogLevel = loglevel
		}
	}

	NodeName = os.Getenv(NodeNameEnvVar)

	if conf := os.Getenv(TapNumRxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", TapNumRxQueuesEnvVar, conf, queues, err)
		}
		TapNumRxQueues = int(queues)
	}

	if conf := os.Getenv(TapNumTxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", TapNumTxQueuesEnvVar, conf, queues, err)
		}
		TapNumTxQueues = int(queues)
	}

	if conf := os.Getenv(TapGSOEnvVar); conf != "" {
		gso, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapGSOEnvVar, conf, gso, err)
		}
		TapGSOEnabled = gso
	}

	if conf := os.Getenv(EnableIPSecEnvVar); conf != "" {
		enableIPSec, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnableIPSecEnvVar, conf, enableIPSec, err)
		}
		EnableIPSec = enableIPSec
	}

	if conf := os.Getenv(CrossIpsecTunnelsEnvVar); conf != "" {
		crossIpsecTunnels, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", CrossIpsecTunnelsEnvVar, conf, crossIpsecTunnels, err)
		}
		CrossIpsecTunnels = crossIpsecTunnels
	}

	if conf := os.Getenv(EnableServicesEnvVar); conf != "" {
		enableServices, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", EnableServicesEnvVar, conf, enableServices, err)
		}
		EnableServices = enableServices
	}

	if conf := os.Getenv(IPSecExtraAddressesEnvVar); conf != "" {
		extraAddressCount, err := strconv.ParseInt(conf, 10, 8)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", IPSecExtraAddressesEnvVar, conf, extraAddressCount, err)
		}
		IpsecAddressCount = int(extraAddressCount) + 1
	}

	if conf := os.Getenv(TapQueueSizeEnvVar); conf != "" {
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

	psk := os.Getenv(IPSecIkev2PskEnvVar)
	if EnableIPSec && psk == "" {
		return errors.New("IKEv2 PSK not configured: nothing found in CALICOVPP_IPSEC_IKEV2_PSK environment variable")
	}
	IPSecIkev2Psk = psk

	servicePrefixStr := os.Getenv(ServicePrefixEnvVar)
	for _, prefixStr := range strings.Split(servicePrefixStr, ",") {
		_, serviceCIDR, err := net.ParseCIDR(prefixStr)
		if err != nil {
			return errors.Errorf("invalid service prefix configuration: %s %s", prefixStr, err)
		}
		ServiceCIDRs = append(ServiceCIDRs, serviceCIDR)
	}

	switch os.Getenv(TapRxModeEnvVar) {
	case "interrupt":
		TapRxMode = types.Interrupt
	case "polling":
		TapRxMode = types.Polling
	case "adaptive":
		TapRxMode = types.Adaptative
	default:
		TapRxMode = defaultRxMode
	}

	if infostore := os.Getenv(InfoStoreVar); infostore != "" {
		infostoreFlag, err := strconv.ParseBool(infostore)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", InfoStoreVar, infostore, infostoreFlag, err)
		}
		InfoStoreEnable = infostoreFlag
	}

	log.Infof("Config:TapNumRxQueues    %d", TapNumRxQueues)
	log.Infof("Config:TapGSOEnabled     %t", TapGSOEnabled)
	log.Infof("Config:EnableServices    %t", EnableServices)
	log.Infof("Config:EnableIPSec       %t", EnableIPSec)
	log.Infof("Config:CrossIpsecTunnels %t", CrossIpsecTunnels)
	log.Infof("Config:IpsecAddressCount %d", IpsecAddressCount)
	log.Infof("Config:RxMode            %d", TapRxMode)
	log.Infof("Config:BgpLogLevel       %d", BgpLogLevel)
	log.Infof("Config:InfoStore         %t", InfoStoreEnable)

	return nil
}
