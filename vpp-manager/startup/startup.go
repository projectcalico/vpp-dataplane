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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/uplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
)

func NewVppManagerParams() *config.VppManagerParams {
	params := &config.VppManagerParams{
		NodeAnnotations: utils.FetchNodeAnnotations(*config.NodeName),
		Interfaces:      make(map[string]*config.VppManagerInterface),
		InterfacesById:  make([]*config.VppManagerInterface, 0),
	}

	// uplink configuration: This is being deprecated
	if mainInterface := *config.InterfaceVar; mainInterface != "" {
		log.Warn("Use of CALICOVPP_INTERFACE, CALICOVPP_NATIVE_DRIVER and CALICOVPP_SWAP_DRIVER is deprecated, please use CALICOVPP_INTERFACES instead")
		intf := &config.VppManagerInterface{
			Spec: config.UplinkInterfaceSpec{
				InterfaceName: mainInterface,
				VppDriver:     strings.ToLower(*config.NativeDriver),
				NewDriverName: *config.SwapDriver,
			},
		}
		params.Interfaces[intf.Spec.InterfaceName] = intf
		params.InterfacesById = append(params.InterfacesById, intf)
	}

	// uplinks configuration
	isMainCount := 0
	for _, spec := range config.GetCalicoVppInterfaces().UplinkInterfaces {
		intf := &config.VppManagerInterface{Spec: spec}
		params.Interfaces[intf.Spec.InterfaceName] = intf
		params.InterfacesById = append(params.InterfacesById, intf)
		if intf.Spec.IsMain {
			isMainCount++
		}
	}
	if len(params.Interfaces) == 0 {
		log.Panicf("No interface specified. Specify an interface through the environment variable")
	}
	if isMainCount == 0 {
		// By default the first interface is main
		params.InterfacesById[0].Spec.IsMain = true
	} else if isMainCount > 1 {
		log.Panicf("Too many interfaces tagged Main")
	}

	for index, intf := range params.InterfacesById {
		intf.Spec.SetUplinkInterfaceIndex(index)
		err := intf.Spec.Validate(nil)
		if err != nil {
			log.Panicf("error validating uplink %s %s", intf.Spec.String(), err)
		}
	}

	// Drivers
	params.LoadedDrivers = make(map[string]bool)
	vfioLoaded, err := utils.IsDriverLoaded(config.DriverVfioPci)
	if err != nil {
		log.Warnf("Error determining whether %s is loaded", config.DriverVfioPci)
	}
	params.LoadedDrivers[config.DriverVfioPci] = vfioLoaded
	uioLoaded, err := utils.IsDriverLoaded(config.DriverUioPciGeneric)
	if err != nil {
		log.Warnf("Error determining whether %s is loaded", config.DriverUioPciGeneric)
	}
	params.LoadedDrivers[config.DriverUioPciGeneric] = uioLoaded

	// AF XDP support
	kernel, err := utils.GetOsKernelVersion()
	if err != nil {
		log.Warnf("Error getting os kernel version %v", err)
	} else {
		params.KernelVersion = kernel
	}

	// Hugepages
	nrHugepages, err := utils.GetNrHugepages()
	if err != nil {
		log.Warnf("Error getting nrHugepages %v", err)
	}
	params.AvailableHugePages = nrHugepages

	/* Iommu */
	params.InitialVfioEnableUnsafeNoIommuMode, err = utils.GetVfioEnableUnsafeNoIommuMode()
	if err != nil {
		log.Warnf("Error getting vfio iommu state %v", err)
	}

	for _, intf := range params.Interfaces {
		uplinkState, err := loadInterfaceConfigFromLinux(intf.Spec)
		if err != nil {
			log.Panicf("Could not load config from linux (%v)", err)
		}
		intf.State = uplinkState
		intf.Driver = uplink.NewUplinkDriver(
			intf.Driver.GetName(),
			params,
			intf,
		)
	}
	return params

}

func PrintVppManagerConfig(params *config.VppManagerParams) {
	log.Infof("-- Environment --")
	log.Infof("Hugepages            %d", params.AvailableHugePages)
	log.Infof("KernelVersion        %s", params.KernelVersion)
	log.Infof("Drivers              %v", params.LoadedDrivers)
	log.Infof("initial iommu status %s", params.InitialVfioEnableUnsafeNoIommuMode)
	for _, intf := range params.Interfaces {
		log.Infof("-- Interface Spec --")
		log.Infof("Interface Name:      %s", intf.Spec.InterfaceName)
		log.Infof("Native Driver:       %s", intf.Spec.VppDriver)
		log.Infof("New Drive Name:      %s", intf.Spec.NewDriverName)
		log.Infof("PHY target #Queues   rx:%d tx:%d", intf.Spec.NumRxQueues, intf.Spec.NumTxQueues)
		log.Infof("Tap MTU:             %d", intf.Spec.Mtu)

		log.Infof("-- Interface config --")
		log.Infof("Node IP4:            %s", intf.State.NodeIP4)
		log.Infof("Node IP6:            %s", intf.State.NodeIP6)
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
