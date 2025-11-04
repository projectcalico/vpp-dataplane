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

package podinterface

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

type LoopbackPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func NewLoopbackPodInterfaceDriver(vpp *vpplink.VppLink, cache *cache.Cache, log *logrus.Entry) *LoopbackPodInterfaceDriver {
	return &LoopbackPodInterfaceDriver{
		PodInterfaceDriverData: PodInterfaceDriverData{
			vpp:   vpp,
			log:   log,
			cache: cache,
			Name:  "loopback",
		},
	}
}

func (i *LoopbackPodInterfaceDriver) CreateInterface(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	swIfIndex, err := i.vpp.CreateLoopback(common.ContainerSideMacAddress)
	if err != nil {
		return errors.Wrapf(err, "Error creating loopback")
	} else {
		stack.Push(i.vpp.DeleteLoopback, swIfIndex)
	}
	podSpec.LoopbackSwIfIndex = swIfIndex

	for _, ipFamily := range vpplink.IPFamilies {
		vrfID := podSpec.GetVrfID(ipFamily)
		err = i.vpp.SetInterfaceVRF(swIfIndex, vrfID, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "Error setting loopback %d in per pod vrf", swIfIndex)
		}
	}

	err = i.DoPodIfNatConfiguration(podSpec, stack, podSpec.LoopbackSwIfIndex)
	if err != nil {
		return err
	}

	for _, containerIP := range podSpec.GetContainerIPs() {
		err = i.vpp.AddInterfaceAddress(swIfIndex, containerIP)
		if err != nil {
			return errors.Wrapf(err, "Error adding address %s to pod loopback interface", containerIP)
		}
	}

	return nil
}

func (i *LoopbackPodInterfaceDriver) DeleteInterface(podSpec *model.LocalPodSpec) {
	i.UndoPodIfNatConfiguration(podSpec.LoopbackSwIfIndex)

	err := i.vpp.DeleteLoopback(podSpec.LoopbackSwIfIndex)
	if err != nil {
		i.log.Errorf("Error deleting Loopback %s", err)
	}
}
