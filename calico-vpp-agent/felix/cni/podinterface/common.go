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

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type PodInterfaceDriverData struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache
	Name  string
}

func (i *PodInterfaceDriverData) SpreadTxQueuesOnWorkers(swIfIndex uint32, numTxQueues int) (err error) {
	i.log.WithFields(map[string]interface{}{
		"swIfIndex": swIfIndex,
	}).Debugf("Spreading %d TX queues on %d workers for pod interface: %v", numTxQueues, i.cache.NumDataThreads, i.Name)

	// set first tx queue for main worker
	err = i.vpp.SetInterfaceTxPlacement(swIfIndex, 0 /* queue */, 0 /* worker */)
	if err != nil {
		return err
	}
	// share tx queues between the rest of workers
	if i.cache.NumDataThreads > 0 {
		for txq := 1; txq < numTxQueues; txq++ {
			err = i.vpp.SetInterfaceTxPlacement(swIfIndex, txq /* queue */, (txq-1)%(i.cache.NumDataThreads)+1 /* worker */)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *PodInterfaceDriverData) SpreadRxQueuesOnWorkers(swIfIndex uint32, numRxQueues int) {
	i.log.WithFields(map[string]interface{}{
		"swIfIndex": swIfIndex,
	}).Debugf("Spreading %d RX queues on %d workers for pod interface: %v", numRxQueues, i.cache.NumDataThreads, i.Name)

	if i.cache.NumDataThreads > 0 {
		for queue := 0; queue < numRxQueues; queue++ {
			worker := (int(swIfIndex)*numRxQueues + queue) % i.cache.NumDataThreads
			err := i.vpp.SetInterfaceRxPlacement(swIfIndex, queue, worker, false /* main */)
			if err != nil {
				i.log.Warnf("failed to set if[%d] queue:%d worker:%d (tot workers %d): %v", swIfIndex, queue, worker, i.cache.NumDataThreads, err)
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

	for _, ipFamily := range vpplink.IPFamilies {
		err = i.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIP6, false /*isEnable*/)
		if err != nil {
			i.log.Errorf("Error disabling %s snat %v", ipFamily.Str, err)
		}
	}
}

func (i *PodInterfaceDriverData) DoPodIfNatConfiguration(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) (err error) {
	if podSpec.NeedsSnat {
		i.log.Infof("pod(add) Enable interface[%d] SNAT", swIfIndex)
		for _, ipFamily := range vpplink.IPFamilies {
			err = i.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIP6, true /*isEnable*/)
			if err != nil {
				return errors.Wrapf(err, "Error enabling %s snat", ipFamily.Str)
			} else {
				stack.Push(i.vpp.EnableDisableCnatSNAT, swIfIndex, ipFamily.IsIP6, false)
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
	err := i.vpp.InterfaceAdminDown(swIfIndex)
	if err != nil {
		i.log.Errorf("InterfaceAdminDown errored %s", err)
	}
}

func (i *PodInterfaceDriverData) DoPodInterfaceConfiguration(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, ifSpec config.InterfaceSpec, swIfIndex uint32) (err error) {
	for _, ipFamily := range vpplink.IPFamilies {
		vrfID := podSpec.GetVrfID(ipFamily)
		err = i.vpp.SetInterfaceVRF(swIfIndex, vrfID, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "error setting vpp if[%d] in pod vrf", swIfIndex)
		}
	}

	if !*ifSpec.IsL3 {
		/* L2 */
		err = i.vpp.SetPromiscOn(swIfIndex)
		if err != nil {
			return errors.Wrapf(err, "Error setting memif promisc")
		}
	}

	err = i.vpp.SetInterfaceMtu(swIfIndex, vpplink.CalicoVppMaxMTu)
	if err != nil {
		return errors.Wrapf(err, "Error setting MTU on pod interface")
	}

	err = i.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting new pod if up")
	}

	err = i.vpp.SetInterfaceRxMode(swIfIndex, types.AllQueues, ifSpec.GetRxModeWithDefault(types.AdaptativeRxMode))
	if err != nil {
		return errors.Wrapf(err, "error SetInterfaceRxMode on pod if interface")
	}

	err = i.vpp.InterfaceSetUnnumbered(swIfIndex, podSpec.LoopbackSwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting interface unnumbered")
	}

	return nil
}
