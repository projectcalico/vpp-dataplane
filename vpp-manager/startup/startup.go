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
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
)

func NewVppManagerParams() *config.VppManagerParams {
	params := &config.VppManagerParams{
		NodeAnnotations: utils.FetchNodeAnnotations(*config.NodeName),
	}

	/* uplink configuration: This is being deprecated */
	if mainInterface := *config.InterfaceVar; mainInterface != "" {
		log.Warn("Use of CALICOVPP_INTERFACE, CALICOVPP_NATIVE_DRIVER and CALICOVPP_SWAP_DRIVER is deprecated, please use CALICOVPP_INTERFACES instead")
		params.UplinksSpecs = []config.UplinkInterfaceSpec{{
			InterfaceName: mainInterface,
			VppDriver:     strings.ToLower(*config.NativeDriver),
			NewDriverName: *config.SwapDriver,
		}}
	}

	/* uplinks configuration */
	for index, uplink := range config.GetCalicoVppInterfaces().UplinkInterfaces {
		_ = uplink.Validate(nil, index == 0)
		params.UplinksSpecs = append(params.UplinksSpecs, uplink)
	}
	if len(params.UplinksSpecs) == 0 {
		log.Panicf("No interface specified. Specify an interface through the environment variable")
	}
	params.UplinksSpecs[0].IsMain = &config.True

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

	return params

}

func PrintVppManagerConfig(params *config.VppManagerParams, confs []*config.LinuxInterfaceState) {
	log.Infof("-- Environment --")
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
		log.Infof("Tap MTU:             %d", ifSpec.Mtu)

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
