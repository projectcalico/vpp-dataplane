// Copyright (C) 2021 Cisco Systems Inc.
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

package pod_interface

import (
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

type MemifPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func NewMemifPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *MemifPodInterfaceDriver {
	i := &MemifPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.isL3 = false
	i.name = storage.VppMemifName
	i.IfType = storage.VppMemif
	return i
}

func (i *MemifPodInterfaceDriver) Create(podSpec *storage.LocalPodSpec) (swIfIndex uint32, err error) {
	swIfIndex = i.SearchPodInterface(podSpec)
	if swIfIndex == vpplink.INVALID_SW_IF_INDEX {
		swIfIndex, err = i.AddPodInterfaceToVPP(podSpec)
		if err != nil {
			return vpplink.INVALID_SW_IF_INDEX, err
		}
	}
	err = i.DoPodInterfaceConfiguration(podSpec, swIfIndex)
	if err != nil {
		return swIfIndex, err
	}

	if i.IfType == podSpec.DefaultIfType {
		err = i.DoPodRoutesConfiguration(podSpec, swIfIndex)
	} else {
		err = i.DoPodAbfConfiguration(podSpec, swIfIndex)
	}
	if err != nil {
		return swIfIndex, err
	}
	return swIfIndex, nil
}

func (i *MemifPodInterfaceDriver) Delete(podSpec *storage.LocalPodSpec) {
	swIfIndex := i.SearchPodInterface(podSpec)
	if swIfIndex == vpplink.INVALID_SW_IF_INDEX {
		i.log.Debugf("interface not found %s", podSpec.GetInterfaceTag(i.name))
		return
	}
	i.UndoPodAbfConfiguration(swIfIndex)

	i.UndoPodInterfaceConfiguration(swIfIndex)
	i.DelPodInterfaceFromVPP(swIfIndex)
}

func (i *MemifPodInterfaceDriver) DelPodInterfaceFromVPP(swIfIndex uint32) {
	err := i.vpp.DeleteMemif(&types.Memif{
		SwIfIndex: swIfIndex,
		SocketId:  0, /* TODO properly cleanup sockets */
	})
	if err != nil {
		i.log.Warnf("Error deleting memif[%d] %s", swIfIndex, err)
	}
	i.log.Infof("deleted memif[%d]", swIfIndex)
}

func (i *MemifPodInterfaceDriver) AddPodInterfaceToVPP(podSpec *storage.LocalPodSpec) (uint32, error) {
	memifTag := podSpec.GetInterfaceTag(i.name)
	// Clean up old tun if one is found with this tag
	err, swIfIndex := i.vpp.SearchInterfaceWithTag(memifTag)
	if err != nil {
		i.log.Errorf("Error while searching tun %s : %v", memifTag, err)
	} else if swIfIndex != vpplink.INVALID_SW_IF_INDEX {
		return swIfIndex, nil
	}

	// Create new tun
	memif := &types.Memif{
		Role:           types.MemifMaster,
		Mode:           types.MemifModeEthernet,
		NumRxQueues:    config.TapNumRxQueues,
		NumTxQueues:    config.TapNumTxQueues,
		QueueSize:      config.TapRxQueueSize,
		SocketFileName: "@memif",
		Namespace:      podSpec.NetnsName,
	}
	err = i.vpp.CreateMemif(memif)
	if err != nil {
		return 0, err
	}

	err = i.vpp.AddInterfaceTag(memif.SwIfIndex, memifTag)
	if err != nil {
		return 0, err
	}

	if config.TapGSOEnabled {
		err = i.vpp.EnableGSOFeature(memif.SwIfIndex)
		if err != nil {
			return 0, errors.Wrap(err, "Error enabling GSO on memif")
		}
	}

	return memif.SwIfIndex, nil
}
