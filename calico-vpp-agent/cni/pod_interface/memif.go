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
	"fmt"
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
	i.name = "memif"
	return i
}

func (i *MemifPodInterfaceDriver) CreateInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	socketId, err := i.vpp.AddMemifSocketFileName(fmt.Sprintf("@netns:%s%s", podSpec.NetnsName, config.MemifSocketName))
	if err != nil {
		return err
	} else {
		stack.Push(i.vpp.DelMemifSocketFileName, socketId)
	}
	podSpec.MemifSocketId = socketId

	// Create new tun
	memif := &types.Memif{
		Role:        types.MemifMaster,
		Mode:        types.MemifModeEthernet,
		NumRxQueues: config.TapNumRxQueues,
		NumTxQueues: config.TapNumTxQueues,
		QueueSize:   config.TapRxQueueSize,
		SocketId:    socketId,
	}
	if podSpec.MemifIsL3 {
		memif.Mode = types.MemifModeIP
	}

	err = i.vpp.CreateMemif(memif)
	if err != nil {
		return err
	} else {
		stack.Push(i.vpp.DeleteMemif, memif.SwIfIndex)
	}
	podSpec.MemifSwIfIndex = memif.SwIfIndex

	err = i.vpp.SetInterfaceTag(memif.SwIfIndex, podSpec.GetInterfaceTag(i.name))
	if err != nil {
		return err
	}

	if config.PodGSOEnabled {
		err = i.vpp.EnableGSOFeature(memif.SwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on memif")
		}
	}

	err = i.DoPodIfNatConfiguration(podSpec, stack, memif.SwIfIndex)
	if err != nil {
		return err
	}

	err = i.DoPodInterfaceConfiguration(podSpec, stack, memif.SwIfIndex, false /*isL3*/)
	if err != nil {
		return err
	}

	return nil
}

func (i *MemifPodInterfaceDriver) DeleteInterface(podSpec *storage.LocalPodSpec) {
	if podSpec.MemifSwIfIndex == vpplink.InvalidID {
		return
	}

	i.UndoPodInterfaceConfiguration(podSpec.MemifSwIfIndex)
	i.UndoPodIfNatConfiguration(podSpec.MemifSwIfIndex)

	err := i.vpp.DeleteMemif(podSpec.MemifSwIfIndex)
	if err != nil {
		i.log.Warnf("Error deleting memif[%d] %s", podSpec.MemifSwIfIndex, err)
	}

	if podSpec.MemifSocketId != 0 {
		err = i.vpp.DelMemifSocketFileName(podSpec.MemifSocketId)
		if err != nil {
			i.log.Warnf("Error deleting memif[%d] socket[%d] %s", podSpec.MemifSwIfIndex, podSpec.MemifSocketId, err)
		}
	}

	i.log.Infof("Deleted memif[%d]", podSpec.MemifSwIfIndex)

}
