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

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/sirupsen/logrus"
)

type LoopbackPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func NewLoopbackPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *LoopbackPodInterfaceDriver {
	i := &LoopbackPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.Name = "loopback"
	return i
}

func (i *LoopbackPodInterfaceDriver) CreateInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	swIfIndex, err := i.vpp.CreateLoopback(common.ContainerSideMacAddress)
	if err != nil {
		return errors.Wrapf(err, "Error creating loopback")
	} else {
		stack.Push(i.vpp.DeleteLoopback, swIfIndex)
	}
	podSpec.LoopbackSwIfIndex = swIfIndex

	for _, ipFamily := range vpplink.IpFamilies {
		vrfId := podSpec.GetVrfId(ipFamily)
		err = i.vpp.SetInterfaceVRF(swIfIndex, vrfId, ipFamily.IsIp6)
		if err != nil {
			return errors.Wrapf(err, "Error setting loopback %d in per pod vrf", swIfIndex)
		}
	}

	err = i.DoPodIfNatConfiguration(podSpec, stack, podSpec.LoopbackSwIfIndex)
	if err != nil {
		return err
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		err = i.vpp.AddInterfaceAddress(swIfIndex, containerIP)
		if err != nil {
			return errors.Wrapf(err, "Error adding address %s to pod loopback interface", containerIP)
		}
	}

	return nil
}

func (i *LoopbackPodInterfaceDriver) DeleteInterface(podSpec *storage.LocalPodSpec) {
	i.UndoPodIfNatConfiguration(podSpec.LoopbackSwIfIndex)

	err := i.vpp.DeleteLoopback(podSpec.LoopbackSwIfIndex)
	if err != nil {
		i.log.Errorf("Error deleting Loopback %s", err)
	}
}
