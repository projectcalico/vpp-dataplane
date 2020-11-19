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

package startup

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
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

const (
	DefaultTapQueueSize = 1024
	DefaultPhyQueueSize = 1024
	DefaultNumRxQueues  = 1
)

func getVppManagerParams() (params *config.VppManagerParams) {
	params = &config.VppManagerParams{}
	err := parseEnvVariables(params)
	if err != nil {
		log.Panicf("Parse error %v", err)
	}
	getSystemCapabilities(params)
	return params
}

func getSystemCapabilities(params *config.VppManagerParams) {
	/* Drivers */
	params.LoadedDrivers = make(map[string]bool)
	vfioLoaded, err := utils.IsDriverLoaded(config.DRIVER_VFIO_PCI)
	if err != nil {
		log.Warnf("Error determining whether %s is loaded", config.DRIVER_VFIO_PCI)
	}
	params.LoadedDrivers[config.DRIVER_VFIO_PCI] = vfioLoaded
	uioLoaded, err := utils.IsDriverLoaded(config.DRIVER_UIO_PCI_GENERIC)
	if err != nil {
		log.Warnf("Error determining whether %s is loaded", config.DRIVER_UIO_PCI_GENERIC)
	}
	params.LoadedDrivers[config.DRIVER_UIO_PCI_GENERIC] = uioLoaded

	/* AF XDP support */
	kernel, err := utils.GetOsKernelVersion()
	if err != nil {
		log.Warnf("Error getting os kernel version %v", err)
	} else {
		params.KernelVersion = kernel
	}

	/* Hugepages */
	nrHugepages, err := utils.GetNrHugepages()
	if err != nil {
		log.Warnf("Error getting nrHugepages %v", err)
	}
	params.AvailableHugePages = nrHugepages

	/* Iommu */
	iommu, err := utils.IsVfioUnsafeiommu()
	if err != nil {
		log.Warnf("Error getting vfio iommu state %v", err)
	}
	params.VfioUnsafeiommu = iommu

}

func parseEnvVariables(params *config.VppManagerParams) (err error) {
	vppStartupSleep := os.Getenv(VppStartupSleepEnvVar)
	if vppStartupSleep == "" {
		params.VppStartupSleepSeconds = 0
	} else {
		i, err := strconv.ParseInt(vppStartupSleep, 10, 32)
		params.VppStartupSleepSeconds = int(i)
		if err != nil {
			return errors.Wrapf(err, "Error Parsing %s", VppStartupSleepEnvVar)
		}
	}

	params.MainInterface = os.Getenv(InterfaceEnvVar)
	if params.MainInterface == "" {
		return errors.Errorf("No interface specified. Specify an interface through the %s environment variable", InterfaceEnvVar)
	}

	params.ConfigExecTemplate = os.Getenv(ConfigExecTemplateEnvVar)
	params.InitScriptTemplate = os.Getenv(InitScriptTemplateEnvVar)

	params.ConfigTemplate = os.Getenv(ConfigTemplateEnvVar)
	if params.ConfigTemplate == "" {
		return fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}

	params.IfConfigSavePath = os.Getenv(IfConfigPathEnvVar)

	params.NodeName = os.Getenv(NodeNameEnvVar)
	if params.NodeName == "" {
		return errors.Errorf("No node name specified. Specify the NODENAME environment variable")
	}

	servicePrefixStr := os.Getenv(ServicePrefixEnvVar)
	for _, prefixStr := range strings.Split(servicePrefixStr, ",") {
		_, serviceCIDR, err := net.ParseCIDR(prefixStr)
		if err != nil {
			return errors.Errorf("invalid service prefix configuration: %s %s", prefixStr, err)
		}
		params.ServiceCIDRs = append(params.ServiceCIDRs, *serviceCIDR)
	}

	params.VppIpConfSource = os.Getenv(IpConfigEnvVar)
	if params.VppIpConfSource != "linux" { // TODO add dhcp, config file, etc.
		return errors.Errorf("No ip configuration source specified. Specify one of {linux,} through the %s environment variable", IpConfigEnvVar)
	}

	params.CorePattern = os.Getenv(CorePatternEnvVar)

	params.ExtraAddrCount = 0
	if extraAddrConf := os.Getenv(ExtraAddrCountEnvVar); extraAddrConf != "" {
		extraAddrCount, err := strconv.ParseInt(extraAddrConf, 10, 8)
		if err != nil {
			log.Errorf("Couldn't parse %s: %v", ExtraAddrCountEnvVar, err)
		} else {
			params.ExtraAddrCount = int(extraAddrCount)
		}
	}

	params.NativeDriver = ""
	if conf := os.Getenv(NativeDriverEnvVar); conf != "" {
		params.NativeDriver = conf
	}

	params.NumRxQueues = DefaultNumRxQueues
	if conf := os.Getenv(NumRxQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			log.Errorf("Invalid %s configuration: %s parses to %d err %v", NumRxQueuesEnvVar, conf, queues, err)
		} else {
			params.NumRxQueues = int(queues)
		}
	}

	params.NewDriverName = os.Getenv(SwapDriverEnvVar)

	params.RxMode = types.UnformatRxMode(os.Getenv(RxModeEnvVar))
	if params.RxMode == types.UnknownRxMode {
		params.RxMode = defaultRxMode
	}
	params.TapRxMode = types.UnformatRxMode(os.Getenv(TapRxModeEnvVar))
	if params.TapRxMode == types.UnknownRxMode {
		params.TapRxMode = defaultRxMode
	}

	if conf := os.Getenv(DefaultGWEnvVar); conf != "" {
		for _, defaultGWStr := range strings.Split(conf, ",") {
			defaultGW := net.ParseIP(defaultGWStr)
			if defaultGW == nil {
				return errors.Errorf("Unable to parse IP: %s", conf)
			}
			params.DefaultGWs = append(params.DefaultGWs, defaultGW)
		}
	}

	params.TapRxQueueSize = DefaultTapQueueSize
	params.TapTxQueueSize = DefaultTapQueueSize
	if conf := os.Getenv(TapRingSizeEnvVar); conf != "" {
		params.TapRxQueueSize, params.TapTxQueueSize, err = parseRingSize(conf)
		if err != nil {
			return errors.Wrapf(err, "Error parsing %s", TapRingSizeEnvVar)
		}
	}

	params.RxQueueSize = DefaultTapQueueSize
	params.TxQueueSize = DefaultTapQueueSize
	if conf := os.Getenv(RingSizeEnvVar); conf != "" {
		params.RxQueueSize, params.TxQueueSize, err = parseRingSize(conf)
		if err != nil {
			return errors.Wrapf(err, "Error parsing %s", RingSizeEnvVar)
		}
	}
	return nil
}

func parseRingSize(conf string) (int, int, error) {
	rxSize := 0
	txSize := 0
	if conf == "" {
		return 0, 0, fmt.Errorf("Empty configuration")
	}
	sizes := strings.Split(conf, ",")
	if len(sizes) == 1 {
		sz, err := strconv.ParseInt(sizes[0], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("Invalid conf: %s parses to %v err %v", conf, sz, err)
		}
		rxSize = int(sz)
		txSize = int(sz)
	} else if len(sizes) == 2 {
		sz, err := strconv.ParseInt(sizes[0], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("Invalid conf: %s parses to %v err %v", conf, sz, err)
		}
		rxSize = int(sz)
		sz, err = strconv.ParseInt(sizes[1], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("Invalid conf: %s parses to %v err %v", conf, sz, err)
		}
		txSize = int(sz)
	} else {
		return 0, 0, fmt.Errorf("Invalid conf: %s parses to %v", conf, sizes)
	}
	return rxSize, txSize, nil
}

func PrintVppManagerConfig(params *config.VppManagerParams, conf *config.InterfaceConfig) {
	log.Infof("-- Environment --")
	log.Infof("CorePattern:         %s", params.CorePattern)
	log.Infof("ExtraAddrCount:      %d", params.ExtraAddrCount)
	log.Infof("Native driver:       %s", params.NativeDriver)
	log.Infof("RxMode:              %s", types.FormatRxMode(params.RxMode))
	log.Infof("TapRxMode:           %s", types.FormatRxMode(params.TapRxMode))
	log.Infof("Service CIDRs:       [%s]", utils.FormatIPNetSlice(params.ServiceCIDRs))
	log.Infof("Tap Queue Size:      rx:%d tx:%d", params.TapRxQueueSize, params.TapTxQueueSize)
	log.Infof("PHY Queue Size:      rx:%d tx:%d", params.RxQueueSize, params.TxQueueSize)
	log.Infof("PHY target #Queues   rx:%d", params.NumRxQueues)
	log.Infof("Hugepages            %d", params.AvailableHugePages)
	log.Infof("KernelVersion        %s", params.KernelVersion)
	log.Infof("Drivers              %s", params.LoadedDrivers)
	log.Infof("vfio iommu:          %t", params.VfioUnsafeiommu)

	log.Infof("-- Interface config --")
	log.Infof("Node IP4:            %s", conf.NodeIP4)
	log.Infof("Node IP6:            %s", conf.NodeIP6)
	log.Infof("PciId:               %s", conf.PciId)
	log.Infof("Driver:              %s", conf.Driver)
	log.Infof("Linux IF was up ?    %t", conf.IsUp)
	log.Infof("Promisc was on ?     %t", conf.PromiscOn)
	log.Infof("DoSwapDriver:        %t", conf.DoSwapDriver)
	log.Infof("Mac:                 %s", conf.HardwareAddr.String())
	log.Infof("Addresses:           [%s]", conf.AddressString())
	log.Infof("Routes:              [%s]", conf.RouteString())
	log.Infof("PHY original #Queues rx:%d tx:%d", conf.NumRxQueues, conf.NumTxQueues)
}

func runInitScript(params *config.VppManagerParams) error {
	if params.InitScriptTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.InitScriptTemplate, "__VPP_DATAPLANE_IF__", params.MainInterface)
	cmd := exec.Command("/bin/bash", "-c", template)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func PrepareConfiguration() (params *config.VppManagerParams, conf *config.InterfaceConfig) {
	params = getVppManagerParams()
	err := utils.ClearVppManagerFiles()
	if err != nil {
		log.Fatalf("Error clearing config files: %+v", err)
	}

	err = utils.SetCorePattern(params.CorePattern)
	if err != nil {
		log.Fatalf("Error setting core pattern: %s", err)
	}

	err = utils.SetRLimitMemLock()
	if err != nil {
		log.Errorf("Error raising memlock limit, VPP may fail to start: %v", err)
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
