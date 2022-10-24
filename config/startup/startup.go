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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/config/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	log "github.com/sirupsen/logrus"
)

const (
	NodeNameEnvVar      = "NODENAME"
	ServicePrefixEnvVar = "SERVICE_PREFIX"

	/* Deprecated vars */
	/* linux name of the uplink interface to be used by VPP */
	InterfaceEnvVar = "CALICOVPP_INTERFACE"
	/* Driver to consume the uplink with. Leave empty for autoconf */
	NativeDriverEnvVar = "CALICOVPP_NATIVE_DRIVER"
	SwapDriverEnvVar   = "CALICOVPP_SWAP_DRIVER"

	/* Bash template hook points at several points in
	   the VPP lifecycle. See hook/hooks.go */
	BashHookEnvVarPrefix = "CALICOVPP_HOOK_"

	/* Bash script template run before getting config
	   from $CALICOVPP_INTERFACE (same as
	   CALICOVPP_HOOK_BEFORE_IF_READ)*/
	InitScriptTemplateEnvVar = "CALICOVPP_INIT_SCRIPT_TEMPLATE"

	/* Template for VppConfigFile (/etc/vpp/startup.conf)
	   It contains the VPP startup configuration */
	ConfigTemplateEnvVar = "CALICOVPP_CONFIG_TEMPLATE"

	/* Template for VppConfigExecFile (/etc/vpp/startup.exec)
	   It contains the CLI to be executed in vppctl after startup */
	ConfigExecTemplateEnvVar = "CALICOVPP_CONFIG_EXEC_TEMPLATE"

	CalicoVppInitialConfigEnvVar = "CALICOVPP_INITIAL_CONFIG"
	CalicoVppInterfacesEnvVar    = "CALICOVPP_INTERFACES"
	CalicoVppIpsecEnvVar         = "CALICOVPP_IPSEC"
	CalicoVppSrv6EnvVar          = "CALICOVPP_SRV6"
	CalicoVppFeatureGatesEnvVar  = "CALICOVPP_FEATURE_GATES"
	CalicoVppDebugEnvVar         = "CALICOVPP_DEBUG"
)

const (
	/* Allow a maximum number of corefiles, delete older ones */
	maxCoreFiles = 2
)

func GetVppManagerParams() (params *config.VppManagerParams) {
	params = &config.VppManagerParams{}
	True := true
	mainInterfaceSpec := config.UplinkInterfaceSpec{IsMain: &True}
	err := parseEnvVariables(params, mainInterfaceSpec)
	if err != nil {
		log.Panicf("Parse error %v", err)
	}
	getSystemCapabilities(params)
	annotations := utils.FetchNodeAnnotations(params.NodeName)
	params.NodeAnnotations = annotations
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

var supportedEnvVars map[string]bool

func isEnvVarSupported(str string) bool {
	_, found := supportedEnvVars[str]
	return found
}

func getEnvValue(str string) string {
	supportedEnvVars[str] = true
	return os.Getenv(str)
}

func parseEnvVariables(params *config.VppManagerParams, mainInterfaceSpec config.UplinkInterfaceSpec) (err error) {
	supportedEnvVars = make(map[string]bool)

	/* general calicovpp configuration */
	var calicoVppInitialConfig config.CalicoVppInitialConfig
	conf := getEnvValue(CalicoVppInitialConfigEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppInitialConfig)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppInitialConfigEnvVar, conf, err)
		}
	}
	params.IfConfigSavePath = calicoVppInitialConfig.IfConfigSavePath
	params.VppStartupSleepSeconds = calicoVppInitialConfig.VppStartupSleepSeconds
	params.CorePattern = calicoVppInitialConfig.CorePattern
	params.ExtraAddrCount = calicoVppInitialConfig.ExtraAddrCount

	/* interfaces configuration */
	var calicoVppInterfaces config.CalicoVppInterfaces
	conf = getEnvValue(CalicoVppInterfacesEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppInterfaces)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppInterfacesEnvVar, conf, err)
		}
	}
	params.UserSpecifiedMtu = calicoVppInterfaces.Mtu

	/* host tap configuration */
	vpphosttapIfSpec := config.InterfaceSpec{NumRxQueues: 1, NumTxQueues: 1, RxQueueSize: 1024, TxQueueSize: 1024}
	if calicoVppInterfaces.VppHostTapSpec != nil {
		calicoVppInterfaces.VppHostTapSpec.Validate(config.InterfaceSpec{})
		vpphosttapIfSpec = *calicoVppInterfaces.VppHostTapSpec
	}
	params.DefaultTap = vpphosttapIfSpec

	/* uplinks configuration */
	extraInterfacesSpecs := []config.UplinkInterfaceSpec{}
	mainInterfaceDefined := false
	if calicoVppInterfaces.UplinkInterfaces != nil {
		if len(*calicoVppInterfaces.UplinkInterfaces) != 0 {
			mainInterfaceSpec = (*calicoVppInterfaces.UplinkInterfaces)[0]
			mainInterfaceSpec.Validate(config.InterfaceSpec{})
			True := true
			mainInterfaceSpec.IsMain = &True
			mainInterfaceDefined = true
		}
		if len(*calicoVppInterfaces.UplinkInterfaces) > 1 {
			for _, uplink := range (*calicoVppInterfaces.UplinkInterfaces)[1:] {
				uplink.Validate(config.InterfaceSpec{})
				False := false
				uplink.IsMain = &False
				extraInterfacesSpecs = append(extraInterfacesSpecs, uplink)
				if uplink.VppDriver == "" {
					return errors.Errorf("vpp driver should be specified for multiple uplink interfaces")
				}
			}
		}
	}
	/* uplink configuration: This is being deprecated */
	if !mainInterfaceDefined {
		log.Warn("Use of CALICOVPP_INTERFACE, CALICOVPP_NATIVE_DRIVER and CALICOVPP_SWAP_DRIVER is deprecated, please use CALICOVPP_INTERFACES instead")

		mainInterface := getEnvValue(InterfaceEnvVar)
		if mainInterface == "" {
			return errors.Errorf("No interface specified. Specify an interface through the %s environment variable", InterfaceEnvVar)
		}
		mainInterfaceSpec.InterfaceName = mainInterface

		mainInterfaceSpec.VppDriver = ""
		if conf := getEnvValue(NativeDriverEnvVar); conf != "" {
			mainInterfaceSpec.VppDriver = strings.ToLower(conf)
		}

		mainInterfaceSpec.NewDriverName = getEnvValue(SwapDriverEnvVar)
	}

	params.UplinksSpecs = []config.UplinkInterfaceSpec{mainInterfaceSpec}
	params.UplinksSpecs = append(params.UplinksSpecs, extraInterfacesSpecs...)

	/* general calicovpp configuration */
	params.ConfigExecTemplate = getEnvValue(ConfigExecTemplateEnvVar)
	for _, hookName := range hooks.AllHooks {
		if conf := getEnvValue(fmt.Sprintf("%s%s", BashHookEnvVarPrefix, hookName)); conf != "" {
			hooks.RegisterBashHook(hookName, conf)
		}
	}
	if conf := getEnvValue(InitScriptTemplateEnvVar); conf != "" {
		hooks.RegisterBashHook(hooks.BEFORE_IF_READ, conf)
	}

	// Add default hook if none specified
	for _, hookName := range []string{hooks.VPP_RUNNING, hooks.VPP_DONE_OK, hooks.VPP_ERRORED} {
		if hooks.HookCount(hookName) == 0 {
			hooks.RegisterBashHook(hookName, hooks.DEFAULT_RESTART_SCRIPT)
		}
	}

	params.ConfigTemplate = getEnvValue(ConfigTemplateEnvVar)
	if params.ConfigTemplate == "" {
		return fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}

	params.NodeName = getEnvValue(NodeNameEnvVar)
	if params.NodeName == "" {
		return errors.Errorf("No node name specified. Specify the NODENAME environment variable")
	}

	servicePrefixStr := getEnvValue(ServicePrefixEnvVar)
	for _, prefixStr := range strings.Split(servicePrefixStr, ",") {
		_, serviceCIDR, err := net.ParseCIDR(prefixStr)
		if err != nil {
			return errors.Errorf("invalid service prefix configuration: %s %s", prefixStr, err)
		}
		params.ServiceCIDRs = append(params.ServiceCIDRs, *serviceCIDR)
	}

	defaultGW := calicoVppInitialConfig.DefaultGWs
	if defaultGW != "" {
		for _, defaultGWStr := range strings.Split(defaultGW, ",") {
			defaultGW := net.ParseIP(defaultGWStr)
			if defaultGW == nil {
				return errors.Errorf("Unable to parse IP: %s", conf)
			}
			params.DefaultGWs = append(params.DefaultGWs, defaultGW)
		}
	}

	/* debug */
	var calicoVppDebug config.CalicoVppDebug
	conf = getEnvValue(CalicoVppDebugEnvVar)
	if conf != "" {
		err := json.Unmarshal([]byte(conf), &calicoVppDebug)
		if err != nil {
			return errors.Errorf("Invalid %s configuration: failed to parse '%s' as JSON: %s", CalicoVppDebugEnvVar, conf, err)
		}
	}
	if calicoVppDebug.GSOEnabled != nil {
		params.EnableGSO = *calicoVppDebug.GSOEnabled
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

func PrintVppManagerConfig(params *config.VppManagerParams, confs []*config.LinuxInterfaceState) {
	log.Infof("-- Environment --")
	log.Infof("CorePattern:         %s", params.CorePattern)
	log.Infof("ExtraAddrCount:      %d", params.ExtraAddrCount)
	log.Infof("Tap MTU override:    %d", params.UserSpecifiedMtu)
	log.Infof("Service CIDRs:       [%s]", utils.FormatIPNetSlice(params.ServiceCIDRs))
	log.Infof("Hugepages            %d", params.AvailableHugePages)
	log.Infof("KernelVersion        %s", params.KernelVersion)
	log.Infof("Drivers              %v", params.LoadedDrivers)
	log.Infof("vfio iommu:          %t", params.VfioUnsafeiommu)
	for _, ifSpec := range params.UplinksSpecs {
		log.Infof("-- Interface Spec --")
		log.Infof("Interface Name:      %s", ifSpec.InterfaceName)
		log.Infof("Native Driver:       %s", ifSpec.VppDriver)
		log.Infof("New Drive Name:      %s", ifSpec.NewDriverName)
		log.Infof("PHY target #Queues   rx:%d tx:%d", ifSpec.NumRxQueues, ifSpec.NumTxQueues)
	}
	for _, conf := range confs {
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
		log.Infof("MTU                  %d", conf.Mtu)
		log.Infof("isTunTap             %t", conf.IsTunTap)
		log.Infof("isVeth               %t", conf.IsVeth)
	}
}

func PrepareConfiguration(params *config.VppManagerParams) (conf []*config.LinuxInterfaceState) {
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

	conf, err = getInterfaceConfig(params)
	if err != nil {
		log.Fatalf("Error getting initial interface configuration: %s", err)
	}

	return conf
}

type timeSlice []time.Time

func (s timeSlice) Less(i, j int) bool { return s[i].Before(s[j]) }
func (s timeSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s timeSlice) Len() int           { return len(s) }

func CleanupCoreFiles(corePattern string) error {
	files := make(map[time.Time]string)
	var times timeSlice = []time.Time{}
	dir := corePattern[:strings.LastIndex(corePattern, "/")]
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if path != dir {
			files[info.ModTime()] = path
			times = append(times, info.ModTime())
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(files) > maxCoreFiles {
		sort.Sort(times)
		for _, time := range times[:len(times)-maxCoreFiles] {
			os.Remove(files[time])
		}
	}

	if len(times) > 0 && maxCoreFiles > 0 {
		PrintLastBackTrace(files[times[0]])
	}
	return nil
}

func PrintLastBackTrace(coreFile string) {
	if _, err := os.Stat("/usr/bin/gdb"); os.IsNotExist(err) {
		log.Infof("Found previous coredump %s, missing gdb for stacktrace", coreFile)
	} else {
		log.Infof("Found previous coredump %s, trying to print stacktrace", coreFile)
		cmd := exec.Command("/usr/bin/gdb", "-ex", "bt", "-ex", "q", "vpp", coreFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Start()
		if err != nil {
			log.Infof("gdb returned %s", err)
		}
	}
}
