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

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	log "github.com/sirupsen/logrus"
)

const (
	NodeNameEnvVar           = "NODENAME"
	IpConfigEnvVar           = "CALICOVPP_IP_CONFIG"
	RxModeEnvVar             = "CALICOVPP_RX_MODE"
	NumRxQueuesEnvVar        = "CALICOVPP_RX_QUEUES"
	TapRxModeEnvVar          = "CALICOVPP_TAP_RX_MODE"
	InterfaceEnvVar          = "CALICOVPP_INTERFACE"
	ConfigTemplateEnvVar     = "CALICOVPP_CONFIG_TEMPLATE"
	ConfigExecTemplateEnvVar = "CALICOVPP_CONFIG_EXEC_TEMPLATE"
	InitScriptTemplateEnvVar = "CALICOVPP_INIT_SCRIPT_TEMPLATE"
	IfConfigPathEnvVar       = "CALICOVPP_IF_CONFIG_PATH"
	VppStartupSleepEnvVar    = "CALICOVPP_VPP_STARTUP_SLEEP"
	ExtraAddrCountEnvVar     = "CALICOVPP_CONFIGURE_EXTRA_ADDRESSES"
	CorePatternEnvVar        = "CALICOVPP_CORE_PATTERN"
	TapRingSizeEnvVar        = "CALICOVPP_TAP_RING_SIZE"
	RingSizeEnvVar           = "CALICOVPP_RING_SIZE"
	NativeDriverEnvVar       = "CALICOVPP_NATIVE_DRIVER"
	SwapDriverEnvVar         = "CALICOVPP_SWAP_DRIVER"
	DefaultGWEnvVar          = "CALICOVPP_DEFAULT_GW"
	ServicePrefixEnvVar      = "SERVICE_PREFIX"
	defaultRxMode            = types.Adaptative
)

type VppManagerParams struct {
	vppStartupSleepSeconds  int
	mainInterface           string
	configExecTemplate      string
	configTemplate          string
	initScriptTemplate      string
	nodeName                string
	corePattern             string
	rxMode                  types.RxMode
	tapRxMode               types.RxMode
	serviceCIDRs            []net.IPNet
	vppIpConfSource         string
	extraAddrCount          int
	vppSideMacAddress       net.HardwareAddr
	containerSideMacAddress net.HardwareAddr
	nativeDriver            string
	TapRxQueueSize          int
	TapTxQueueSize          int
	RxQueueSize             int
	TxQueueSize             int
	NumRxQueues             int
	newDriverName           string
	defaultGWs              []net.IP
	ifConfigSavePath        string
}

func parseEnvVariables() (params *VppManagerParams, err error) {
	params = &VppManagerParams{}
	vppStartupSleep := os.Getenv(VppStartupSleepEnvVar)
	if vppStartupSleep == "" {
		params.vppStartupSleepSeconds = 0
	} else {
		i, err := strconv.ParseInt(vppStartupSleep, 10, 32)
		params.vppStartupSleepSeconds = int(i)
		if err != nil {
			return nil, errors.Wrapf(err, "Error Parsing %s", VppStartupSleepEnvVar)
		}
	}

	params.mainInterface = os.Getenv(InterfaceEnvVar)
	if params.mainInterface == "" {
		return nil, errors.Errorf("No interface specified. Specify an interface through the %s environment variable", InterfaceEnvVar)
	}

	params.configExecTemplate = os.Getenv(ConfigExecTemplateEnvVar)
	params.initScriptTemplate = os.Getenv(InitScriptTemplateEnvVar)

	params.configTemplate = os.Getenv(ConfigTemplateEnvVar)
	if params.configTemplate == "" {
		return nil, fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}

	params.ifConfigSavePath = os.Getenv(IfConfigPathEnvVar)

	params.nodeName = os.Getenv(NodeNameEnvVar)
	if params.nodeName == "" {
		return nil, errors.Errorf("No node name specified. Specify the NODENAME environment variable")
	}

	servicePrefixStr := os.Getenv(ServicePrefixEnvVar)
	for _, prefixStr := range strings.Split(servicePrefixStr, ",") {
		_, serviceCIDR, err := net.ParseCIDR(prefixStr)
		if err != nil {
			return nil, errors.Errorf("invalid service prefix configuration: %s %s", prefixStr, err)
		}
		params.serviceCIDRs = append(params.serviceCIDRs, *serviceCIDR)
	}

	params.vppIpConfSource = os.Getenv(IpConfigEnvVar)
	if params.vppIpConfSource != "linux" { // TODO add dhcp, config file, etc.
		return nil, errors.Errorf("No ip configuration source specified. Specify one of {linux,} through the %s environment variable", IpConfigEnvVar)
	}

	params.corePattern = os.Getenv(CorePatternEnvVar)

	params.extraAddrCount = 0
	if extraAddrConf := os.Getenv(ExtraAddrCountEnvVar); extraAddrConf != "" {
		extraAddrCount, err := strconv.ParseInt(extraAddrConf, 10, 8)
		if err != nil {
			log.Errorf("Couldn't parse %s: %v", ExtraAddrCountEnvVar, err)
		} else {
			params.extraAddrCount = int(extraAddrCount)
		}
	}

	params.nativeDriver = NATIVE_DRIVER_NONE
	if conf := os.Getenv(NativeDriverEnvVar); conf != "" {
		params.nativeDriver = conf
	}

	if conf := os.Getenv(NumRxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return nil, fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", NumRxQueuesEnvVar, conf, queues, err)
		}
		params.NumRxQueues = int(queues)
	}

	params.newDriverName = os.Getenv(SwapDriverEnvVar)

	params.rxMode = types.UnformatRxMode(os.Getenv(RxModeEnvVar))
	if params.rxMode == types.UnknownRxMode {
		params.rxMode = defaultRxMode
	}
	params.tapRxMode = types.UnformatRxMode(os.Getenv(TapRxModeEnvVar))
	if params.tapRxMode == types.UnknownRxMode {
		params.tapRxMode = defaultRxMode
	}

	if conf := os.Getenv(DefaultGWEnvVar); conf != "" {
		for _, defaultGWStr := range strings.Split(conf, ",") {
			defaultGW := net.ParseIP(defaultGWStr)
			if defaultGW == nil {
				return nil, errors.Errorf("Unable to parse IP: %s", conf)
			}
			params.defaultGWs = append(params.defaultGWs, defaultGW)
		}
	}
	params.TapRxQueueSize, params.TapTxQueueSize, err = parseRingSize(TapRingSizeEnvVar)
	if err != nil {
		return nil, err
	}
	params.RxQueueSize, params.TxQueueSize, err = parseRingSize(RingSizeEnvVar)
	if err != nil {
		return nil, err
	}
	return params, nil
}

func parseRingSize(envVar string) (int, int, error) {
	rxSize := 0
	txSize := 0
	if conf := os.Getenv(envVar); conf != "" {
		sizes := strings.Split(conf, ",")
		if len(sizes) == 1 {
			sz, err := strconv.ParseInt(sizes[0], 10, 32)
			if err != nil {
				return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", envVar, conf, sz, err)
			}
			rxSize = int(sz)
			txSize = int(sz)
		} else if len(sizes) == 2 {
			sz, err := strconv.ParseInt(sizes[0], 10, 32)
			if err != nil {
				return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", envVar, conf, sz, err)
			}
			rxSize = int(sz)
			sz, err = strconv.ParseInt(sizes[1], 10, 32)
			if err != nil {
				return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", envVar, conf, sz, err)
			}
			txSize = int(sz)
		} else {
			return 0, 0, fmt.Errorf("Invalid %s configuration: %s parses to %v", envVar, conf, sizes)
		}
	}
	return rxSize, txSize, nil
}

func PrintVppManagerConfig(params *VppManagerParams, conf *interfaceConfig) {
	log.Infof("CorePattern:         %s", params.corePattern)
	log.Infof("ExtraAddrCount:      %d", params.extraAddrCount)
	log.Infof("Native driver:       %s", params.nativeDriver)
	log.Infof("RxMode:              %s", types.FormatRxMode(params.rxMode))
	log.Infof("TapRxMode:           %s", types.FormatRxMode(params.tapRxMode))
	log.Infof("Node IP4:            %s", conf.NodeIP4)
	log.Infof("Node IP6:            %s", conf.NodeIP6)
	log.Infof("PciId:               %s", conf.PciId)
	log.Infof("Driver:              %s", conf.Driver)
	log.Infof("Linux if is up:      %t", conf.IsUp)
	log.Infof("Promisc was :        %t", conf.PromiscOn)
	log.Infof("DoSwapDriver:        %t", conf.DoSwapDriver)
	log.Infof("Mac:                 %s", conf.HardwareAddr.String())
	log.Infof("Addresses:           [%s]", conf.AddressString())
	log.Infof("Routes:              [%s]", conf.RouteString())
	log.Infof("Service CIDRs:       [%s]", FormatIPNetSlice(params.serviceCIDRs))
	log.Infof("Tap Queue Size:      rx:%d tx:%d", params.TapRxQueueSize, params.TapTxQueueSize)
	log.Infof("PHY Queue Size:      rx:%d tx:%d", params.RxQueueSize, params.TxQueueSize)
	log.Infof("PHY original #Queues rx:%d tx:%d", conf.NumRxQueues, conf.NumTxQueues)
	log.Infof("PHY target #Queues   rx:%d", params.NumRxQueues)
}

func runInitScript(params *VppManagerParams) error {
	if params.initScriptTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.initScriptTemplate, "__VPP_DATAPLANE_IF__", params.mainInterface)
	cmd := exec.Command("/bin/bash", "-c", template)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func PrepareConfiguration() (params *VppManagerParams, conf *interfaceConfig) {
	params, err := parseEnvVariables()
	if err != nil {
		log.Fatalf("Error parsing env variables: %+v", err)
	}
	err = clearVppManagerFiles()
	if err != nil {
		log.Fatalf("Error clearing config files: %+v", err)
	}

	err = setCorePattern(params.corePattern)
	if err != nil {
		log.Fatalf("Error setting core pattern: %s", err)
	}

	err = setRLimitMemLock()
	if err != nil {
		log.Errorf("Error raising memlock limit, VPP may fail to start: %v", err)
	}

	vfioLoaded, err := isDriverLoaded("vfio-pci")
	if err != nil {
		log.Warnf("Error determining whether vfio-pci is loaded")
	}
	uioLoaded, err := isDriverLoaded("uio_pci_generic")
	if err != nil {
		log.Warnf("Error determining whether vfio-pci is loaded")
	}
	if !vfioLoaded && !uioLoaded {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}

	/* Run this before getLinuxConfig() in case this is a script
	 * that's responsible for creating the interface */
	err = runInitScript(params)
	if err != nil {
		log.Fatalf("Error running init script: %s", err)
	}

	conf, err = getInterfaceConfig(params)
	if err != nil {
		log.Fatalf("Error getting initial interface configuration: %s", err)
	}

	return params, conf
}
