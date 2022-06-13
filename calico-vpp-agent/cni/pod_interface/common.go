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
	"github.com/sirupsen/logrus"

	types2 "git.fd.io/govpp.git/api/v0"
)

type PodInterfaceDriverData struct {
	log          *logrus.Entry
	vpp          *vpplink.VppLink
	name         string
	NDataThreads int
}

func (i *PodInterfaceDriverData) SpreadTxQueuesOnWorkers(swIfIndex uint32, numTxQueues int) (err error) {
	iface := types2.Interface{SwIfIndex: swIfIndex}

	// set first tx queue for main worker
	err = i.vpp.SetInterfaceTxPlacement(&iface, 0 /* queue */, 0 /* worker */)
	if err != nil {
		return err
	}
	// share tx queues between the rest of workers
	if i.NDataThreads > 0 {
		for txq := 1; txq < numTxQueues; txq++ {
			err = i.vpp.SetInterfaceTxPlacement(&iface, txq, (txq-1)%(i.NDataThreads)+1)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *PodInterfaceDriverData) SpreadRxQueuesOnWorkers(swIfIndex uint32) {
	iface := types2.Interface{SwIfIndex: swIfIndex}
	if i.NDataThreads > 0 {
		for queue := 0; queue < config.TapNumRxQueues; queue++ {
			worker := (int(swIfIndex)*config.TapNumRxQueues + queue) % i.NDataThreads
			err := i.vpp.SetInterfaceRxPlacement(&iface, queue, worker, false /* main */)
			if err != nil {
				i.log.Warnf("failed to set if[%d] queue%d worker%d (tot workers %d): %v", swIfIndex, queue, worker, i.NDataThreads, err)
			}
		}
	}
}

func (i *PodInterfaceDriverData) UndoPodIfNatConfiguration(swIfIndex uint32) {
	var err error
	err = i.vpp.RemovePodInterface(swIfIndex)
	if err != nil {
		i.log.Errorf("error deregistering pod interface: %v", err)
	}

	for _, ipFamily := range vpplink.IpFamilies {
		err = i.vpp.DisableCnatSNAT(swIfIndex, ipFamily.IsIp6)
		if err != nil {
			i.log.Errorf("Error disabling %s snat %v", ipFamily.Str, err)
		}
	}
}

func (i *PodInterfaceDriverData) DoPodIfNatConfiguration(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) (err error) {
	if podSpec.NeedsSnat {
		i.log.Infof("pod(add) Enable interface[%d] SNAT", swIfIndex)
		for _, ipFamily := range vpplink.IpFamilies {
			err = i.vpp.EnableCnatSNAT(swIfIndex, ipFamily.IsIp6)
			if err != nil {
				return errors.Wrapf(err, "Error enabling %s snat", ipFamily.Str)
			} else {
				stack.Push(i.vpp.DisableCnatSNAT, swIfIndex, false)
			}
		}
	}

	err = i.vpp.RegisterPodInterface(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error registering pod interface")
	} else {
		stack.Push(i.vpp.RemovePodInterface, swIfIndex)
	}

	err = i.vpp.CnatEnableFeatures(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error configuring nat on pod interface")
	}

	return nil
}

func (i *PodInterfaceDriverData) UndoPodInterfaceConfiguration(swIfIndex uint32) {
	iface := types2.Interface{SwIfIndex: swIfIndex}
	err := i.vpp.InterfaceAdminDown(&iface)
	if err != nil {
		i.log.Errorf("InterfaceAdminDown errored %s", err)
	}
}

func (i *PodInterfaceDriverData) DoPodInterfaceConfiguration(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32, isL3 bool) (err error) {
	iface := types2.Interface{SwIfIndex: swIfIndex}
	i.SpreadRxQueuesOnWorkers(iface.SwIfIndex)

	for _, ipFamily := range vpplink.IpFamilies {
		vrfId := podSpec.GetVrfId(ipFamily)
		err = i.vpp.SetInterfaceVRF(&iface, vrfId, ipFamily.IsIp6)
		if err != nil {
			return errors.Wrapf(err, "error setting vpp if[%d] in pod vrf", swIfIndex)
		}
	}

	if !isL3 {
		/* L2 */
		err = i.vpp.SetPromiscOn(&iface)
		if err != nil {
			return errors.Wrapf(err, "Error setting memif promisc")
		}
	}

	err = i.vpp.SetInterfaceMtu(&iface, types2.MaxMtu)
	if err != nil {
		return errors.Wrapf(err, "Error setting MTU on pod interface")
	}

	err = i.vpp.InterfaceAdminUp(&iface)
	if err != nil {
		return errors.Wrapf(err, "error setting new pod if up")
	}

	// TODO: is this configurable variable or not ?
	err = i.vpp.SetInterfaceRxMode(&iface, types2.AllQueues, config.TapRxMode)
	if err != nil {
		return errors.Wrapf(err, "error SetInterfaceRxMode on pod if interface")
	}

	err = i.vpp.InterfaceSetUnnumbered(swIfIndex, podSpec.LoopbackSwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting interface unnumbered")
	}

	return nil
}
