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
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type MemifPodInterfaceDriver struct {
	PodInterfaceDriverData
}

type dummy struct {
	name string
}

func (d *dummy) Type() string {
	return "dummy"
}
func (d *dummy) Attrs() *netlink.LinkAttrs {
	return &netlink.LinkAttrs{Name: d.name}
}

func NewMemifPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *MemifPodInterfaceDriver {
	i := &MemifPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.Name = "memif"
	return i
}

func (i *MemifPodInterfaceDriver) CreateInterface(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) (err error) {
	memifName := podSpec.InterfaceName
	// if we are in main network (PBL case)
	if podSpec.NetworkName == "" {
		memifName = "vpp/memif-" + podSpec.InterfaceName
	}
	socketID, err := i.vpp.AddMemifSocketFileName(fmt.Sprintf("abstract:%s,netns_name=%s", memifName, podSpec.NetnsName))
	if err != nil {
		return err
	} else {
		stack.Push(i.vpp.DelMemifSocketFileName, socketID)
	}
	podSpec.MemifSocketID = socketID

	var usedIfSpec config.InterfaceSpec
	if podSpec.NetworkName == "" { // PBL case
		usedIfSpec = podSpec.PBLMemifSpec
	} else {
		usedIfSpec = podSpec.IfSpec
	}
	// Create new memif
	memif := &types.Memif{
		Role:        types.MemifMaster,
		Mode:        types.MemifModeEthernet,
		NumRxQueues: usedIfSpec.NumRxQueues,
		NumTxQueues: usedIfSpec.NumTxQueues,
		QueueSize:   usedIfSpec.RxQueueSize,
		SocketID:    socketID,
	}
	if *usedIfSpec.IsL3 {
		memif.Mode = types.MemifModeIP
	}

	err = i.vpp.CreateMemif(memif)
	if err != nil {
		return err
	} else {
		stack.Push(i.vpp.DeleteMemif, memif.SwIfIndex)
	}
	podSpec.MemifSwIfIndex = memif.SwIfIndex

	if *(*config.CalicoVppDebug).SpreadTxQueuesOnWorkers {
		watcher, err := i.vpp.WatchInterfaceEvents(memif.SwIfIndex)
		if err != nil {
			return err
		} else {
			stack.Push(watcher.Stop)
		}
		go func() {
			i.log.WithFields(map[string]interface{}{
				"swIfIndex": memif.SwIfIndex,
			}).Infof("begin watching interface events for: %v", i.Name)

			for event := range watcher.Events() {
				i.log.WithFields(map[string]interface{}{
					"swIfIndex": memif.SwIfIndex,
				}).Infof("processing interface event for %v: %+v", i.Name, event)

				switch event.Type {
				case types.InterfaceEventLinkUp:
					err = i.SpreadTxQueuesOnWorkers(memif.SwIfIndex, memif.NumTxQueues)
					if err != nil {
						i.log.Errorf("error spreading tx queues on workers: %v", err)
					}
					i.SpreadRxQueuesOnWorkers(memif.SwIfIndex, podSpec.IfSpec.NumRxQueues)
				case types.InterfaceEventDeleted: // this might not be needed here, it could be handled internally in the watcher
					watcher.Stop()
				}
			}

			i.log.WithFields(map[string]interface{}{
				"swIfIndex": memif.SwIfIndex,
			}).Infof("done watching interface events for: %v", i.Name)

		}()
	}

	err = i.vpp.SetInterfaceTag(memif.SwIfIndex, podSpec.GetInterfaceTag(i.Name))
	if err != nil {
		return err
	}

	if *config.GetCalicoVppDebug().GSOEnabled {
		err = i.vpp.EnableGSOFeature(memif.SwIfIndex)
		if err != nil {
			return errors.Wrap(err, "Error enabling GSO on memif")
		}
	}

	err = i.DoPodIfNatConfiguration(podSpec, stack, memif.SwIfIndex)
	if err != nil {
		return err
	}

	err = i.DoPodInterfaceConfiguration(podSpec, stack, podSpec.IfSpec, memif.SwIfIndex)
	if err != nil {
		return err
	}

	if doHostSideConf {
		if podSpec.NetworkName != "" {
			i.log.Infof("Creating host side dummy for memif interface %s", podSpec.InterfaceName)
			err = i.createDummy(podSpec.NetnsName, podSpec.InterfaceName)
			if err != nil {
				return err
			} else {
				stack.Push(i.deleteDummy, podSpec.NetnsName, podSpec.InterfaceName)
			}
			err = ns.WithNetNSPath(podSpec.NetnsName, i.configureDummy(podSpec.MemifSwIfIndex, podSpec))
			if err != nil {
				return errors.Wrapf(err, "Error in linux NS config")
			}
		}
	}

	return nil
}

func (i *MemifPodInterfaceDriver) DeleteInterface(podSpec *model.LocalPodSpec) {
	if podSpec.MemifSwIfIndex == vpplink.InvalidID {
		return
	}

	i.UndoPodInterfaceConfiguration(podSpec.MemifSwIfIndex)
	i.UndoPodIfNatConfiguration(podSpec.MemifSwIfIndex)

	err := i.vpp.DeleteMemif(podSpec.MemifSwIfIndex)
	if err != nil {
		i.log.Warnf("Error deleting memif[%d] %s", podSpec.MemifSwIfIndex, err)
	}

	if podSpec.MemifSocketID != 0 {
		err = i.vpp.DelMemifSocketFileName(podSpec.MemifSocketID)
		if err != nil {
			i.log.Warnf("Error deleting memif[%d] socket[%d] %s", podSpec.MemifSwIfIndex, podSpec.MemifSocketID, err)
		}
	}

	i.log.Infof("pod(del) memif swIfIndex=%d", podSpec.MemifSwIfIndex)

}

func (i *MemifPodInterfaceDriver) configureDummy(swIfIndex uint32, podSpec *model.LocalPodSpec) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contDummy, err := netlink.LinkByName(podSpec.InterfaceName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup memifDummy: %v", err)
		}
		hasv4, hasv6 := podSpec.Hasv46()

		// Do the per-IP version set-up.  Add gateway routes etc.
		if hasv6 {
			i.log.Infof("dummy %d in NS has v6", swIfIndex)
			// Make sure ipv6 is enabled in the container/pod network namespace.
			if err = WriteProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.all.disable_ipv6=0: %s", err)
			}
			if err = WriteProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.default.disable_ipv6=0: %s", err)
			}
			if err = WriteProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.lo.disable_ipv6=0: %s", err)
			}
		}

		for _, route := range podSpec.Routes {
			isV6 := route.IP.To4() == nil
			if (isV6 && !hasv6) || (!isV6 && !hasv4) {
				i.log.Infof("Skipping dummy[%d] route for %s", swIfIndex, route.String())
				continue
			}
			i.log.Infof("Add dummy[%d] linux%d route for %s", swIfIndex, contDummy.Attrs().Index, route.String())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contDummy.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       &route,
			})
			if err != nil {
				// TODO : in ipv6 '::' already exists
				i.log.Errorf("Error adding dummy[%d] route for %s", swIfIndex, route.String())
			}
		}

		// Now add the IPs to the container side of the tun.
		for _, containerIP := range podSpec.GetContainerIPs() {
			i.log.Infof("Add dummy[%d] linux%d ip %s", swIfIndex, contDummy.Attrs().Index, containerIP.String())
			err = netlink.AddrAdd(contDummy, &netlink.Addr{IPNet: containerIP})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %s: %v", contDummy.Attrs().Name, err)
			}
		}
		return nil
	}
}

func (i *MemifPodInterfaceDriver) createDummy(netns string, interfaceName string) error {
	memifDummy := dummy{name: interfaceName}
	createDummyInNetns := func(netns ns.NetNS) error {
		err := netlink.LinkAdd(&memifDummy)
		if err != nil {
			return errors.Wrap(err, "unable to create dummy link in linux")
		}
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return errors.Wrap(err, "unable to retrieve name")
		}

		err = netlink.LinkSetUp(link)
		if err != nil {
			return errors.Wrap(err, "unable to set interface up")
		}
		return nil
	}
	err := ns.WithNetNSPath(netns, createDummyInNetns)
	if err != nil {
		return errors.Wrap(err, "unable to create dummy in netns")
	}
	return nil
}

func (i *MemifPodInterfaceDriver) deleteDummy(netns string, interfaceName string) error {
	memifDummy := dummy{name: interfaceName}
	deleteDummyInNetns := func(netns ns.NetNS) error {
		err := netlink.LinkDel(&memifDummy)
		if err != nil {
			return errors.Wrap(err, "unable to delete dummy link in linux")
		}
		return nil
	}
	err := ns.WithNetNSPath(netns, deleteDummyInNetns)
	if err != nil {
		return errors.Wrap(err, "unable to delete dummy in netns")
	}
	return nil
}
