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

package params

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

type UplinkDriver interface {
	PreconfigureLinux() error
	CreateMainVppInterface(vpp *vpplink.VppLink, vppPid int, uplinkSpec *config.UplinkInterfaceSpec) error
	RestoreLinux()
	IsSupported(warn bool) bool
	GetName() string
	UpdateVppConfigFile(template string) string
	GetDefaultRxMode() types.RxMode
}

type VppManagerInterface struct {
	Spec   config.UplinkInterfaceSpec
	State  *config.LinuxInterfaceState
	Driver UplinkDriver
}

type VppManagerParams struct {
	*config.MachineState

	Interfaces     map[string]*VppManagerInterface
	InterfacesByID []*VppManagerInterface

	NodeAnnotations map[string]string
	VppCpusetCPUs   string

	VppConfigFile           string
	VppConfigExecFile       string
	VppPath                 string
	DisableUpdateCalicoNode bool
}

func (p *VppManagerParams) AllInterfacesPhysical() bool {
	for _, intf := range p.InterfacesByID {
		if intf.State.IsTunTap || intf.State.IsVeth {
			return false
		}
	}
	return true
}

func (p *VppManagerParams) TemplateScriptReplace(input string) string {
	template := input
	if len(p.Interfaces) > 0 {
		// We might template scripts before reading interface conf
		template = strings.ReplaceAll(template, "__PCI_DEVICE_ID__", p.InterfacesByID[0].State.PciID)
	}
	for idx, intf := range p.InterfacesByID {
		template = strings.ReplaceAll(template, "__PCI_DEVICE_ID_"+strconv.Itoa(idx)+"__", intf.State.PciID)
	}

	template = strings.ReplaceAll(template, "__CPUSET_CPUS_FIRST__", p.VppCpusetCPUs)
	if len(p.Interfaces) > 0 {
		template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF__", p.InterfacesByID[0].Spec.InterfaceName)
	}
	for idx, intf := range p.InterfacesByID {
		template = strings.ReplaceAll(template, "__VPP_DATAPLANE_IF_"+fmt.Sprintf("%d", idx)+"__", intf.Spec.InterfaceName)
	}
	for key, value := range p.NodeAnnotations {
		template = strings.ReplaceAll(template, fmt.Sprintf("__NODE_ANNOTATION:%s__", key), value)
	}
	return template
}

func (p *VppManagerParams) PrintVppManagerConfig() {
	log.Infof("-- Environment --")
	log.Infof("Hugepages            %d", p.AvailableHugePages)
	log.Infof("KernelVersion        %s", p.KernelVersion)
	log.Infof("Drivers              %v", p.LoadedDrivers)
	log.Infof("initial iommu status %s", p.InitialVfioEnableUnsafeNoIommuMode)
	for _, intf := range p.InterfacesByID {
		log.Infof("-- Interface Spec --")
		log.Infof("Interface Name:      %s", intf.Spec.InterfaceName)
		log.Infof("Native Driver:       %s", intf.Spec.VppDriver)
		log.Infof("New Drive Name:      %s", intf.Spec.NewDriverName)
		log.Infof("PHY target #Queues   rx:%d tx:%d", intf.Spec.NumRxQueues, intf.Spec.NumTxQueues)
		log.Infof("Tap MTU:             %d", intf.Spec.Mtu)

		log.Infof("-- Interface config --")
		log.Infof("Node IP4:            %s", intf.State.GetNodeIP(vpplink.IPFamilyV4))
		log.Infof("Node IP6:            %s", intf.State.GetNodeIP(vpplink.IPFamilyV6))
		log.Infof("PciID:               %s", intf.State.PciID)
		log.Infof("Driver:              %s", intf.State.Driver)
		log.Infof("Linux IF was up ?    %t", intf.State.IsUp)
		log.Infof("Promisc was on ?     %t", intf.State.PromiscOn)
		log.Infof("DoSwapDriver:        %t", intf.State.DoSwapDriver)
		log.Infof("Mac:                 %s", intf.State.HardwareAddr.String())
		log.Infof("Addresses:           [%s]", intf.State.AddressString())
		log.Infof("Routes:              [%s]", intf.State.RouteString())
		log.Infof("PHY original #Queues rx:%d tx:%d", intf.State.NumRxQueues, intf.State.NumTxQueues)
		log.Infof("MTU                  %d", intf.State.Mtu)
		log.Infof("isTunTap             %t", intf.State.IsTunTap)
		log.Infof("isVeth               %t", intf.State.IsVeth)
	}
}

func NewVppManagerParams() *VppManagerParams {
	params := &VppManagerParams{
		MachineState:      config.NewMachineState(),
		NodeAnnotations:   config.FetchNodeAnnotations(*config.NodeName),
		Interfaces:        make(map[string]*VppManagerInterface),
		InterfacesByID:    make([]*VppManagerInterface, 0),
		VppConfigFile:     "/etc/vpp/startup.conf",
		VppConfigExecFile: "/etc/vpp/startup.exec",
		VppPath:           "/usr/bin/vpp",
	}

	// uplink configuration: This is being deprecated
	if mainInterface := *config.InterfaceVar; mainInterface != "" {
		log.Warn("Use of CALICOVPP_INTERFACE, CALICOVPP_NATIVE_DRIVER and CALICOVPP_SWAP_DRIVER is deprecated, please use CALICOVPP_INTERFACES instead")
		intf := &VppManagerInterface{
			Spec: config.UplinkInterfaceSpec{
				InterfaceName: mainInterface,
				VppDriver:     strings.ToLower(*config.NativeDriverEnvVar),
				NewDriverName: *config.SwapDriverEnvVar,
			},
		}
		params.Interfaces[intf.Spec.InterfaceName] = intf
		params.InterfacesByID = append(params.InterfacesByID, intf)
	}

	// uplinks configuration
	isMainCount := 0
	for _, spec := range config.GetCalicoVppInterfaces().UplinkInterfaces {
		intf := &VppManagerInterface{Spec: spec}
		params.Interfaces[intf.Spec.InterfaceName] = intf
		params.InterfacesByID = append(params.InterfacesByID, intf)
		if intf.Spec.IsMain {
			isMainCount++
		}
	}
	if len(params.Interfaces) == 0 {
		log.Panicf("No interface specified. Specify an interface through the environment variable")
	}
	if isMainCount == 0 {
		// By default the first interface is main
		params.InterfacesByID[0].Spec.IsMain = true
	} else if isMainCount > 1 {
		log.Panicf("Too many interfaces tagged Main")
	}

	for index, intf := range params.InterfacesByID {
		intf.Spec.SetUplinkInterfaceIndex(index)
		err := intf.Spec.Validate(nil)
		if err != nil {
			log.Panicf("error validating uplink %s %s", intf.Spec.String(), err)
		}
	}

	var err error
	for _, intf := range params.InterfacesByID {
		intf.State, err = config.NewLinuxInterfaceState(intf.Spec)
		if err != nil {
			log.Panicf("Could not load config from linux (%v)", err)
		}
	}

	// CPUsets
	params.VppCpusetCPUs, err = config.GetCpusetCPU()
	if err != nil {
		log.Warnf("Error getting VppCpusetCPUs %v", err)
	}

	return params

}
