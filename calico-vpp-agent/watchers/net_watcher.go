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

package watchers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	networkv3 "github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/network"
	nadv1 "github.com/projectcalico/vpp-dataplane/v3/multinet-monitor/networkAttachmentDefinition"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

type VRF struct {
	Tables [2]uint32 // one for ipv4, one for ipv6
}

type NetworkDefinition struct {
	VRF               VRF
	Vni               uint32
	Name              string
	LoopbackSwIfIndex uint32
	Range             string
	NetAttachDefs     string
}

type NetWatcher struct {
	log                *logrus.Entry
	vpp                *vpplink.VppLink
	client             client.WithWatch
	stop               chan struct{}
	networkDefinitions map[string]*NetworkDefinition
	nads               map[string]string
	InSync             chan interface{}
	nodeBGPSpec        *common.LocalNodeSpec
}

func NewNetWatcher(vpp *vpplink.VppLink, log *logrus.Entry) *NetWatcher {
	kubernetesClient, err := NewK8SClient(10*time.Second, []func(s *runtime.Scheme) error{networkv3.AddToScheme, nadv1.AddToScheme})
	if err != nil {
		panic(fmt.Errorf("failed instantiating kubernetes client: %v", err))
	}
	w := NetWatcher{
		log:                log,
		vpp:                vpp,
		client:             *kubernetesClient,
		stop:               make(chan struct{}),
		networkDefinitions: make(map[string]*NetworkDefinition),
		nads:               make(map[string]string),
		InSync:             make(chan interface{}),
	}
	return &w
}

func (w *NetWatcher) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	w.nodeBGPSpec = nodeBGPSpec
}

func (w *NetWatcher) WatchNetworks(t *tomb.Tomb) error {
	w.log.Infof("Net watcher starts")
	netList := &networkv3.NetworkList{}
	err := w.client.List(context.Background(), netList, &client.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "Listing Networks failed")
	}
	nadList := &netv1.NetworkAttachmentDefinitionList{}
	err = w.client.List(context.Background(), nadList, &client.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "Listing NetworkAttachmentDefinitions failed")
	}
	for _, net := range netList.Items {
		err := w.OnNetAdded(&net)
		if err != nil {
			return errors.Wrapf(err, "OnNetAdded failed for %v", net)
		}
	}
	for _, nad := range nadList.Items {
		err = w.onNadAdded(&nad)
		if err != nil {
			return errors.Wrapf(err, "OnNadAdded failed for %v", nad)
		}
	}
	w.InSync <- 1
	common.SendEvent(common.CalicoVppEvent{
		Type: common.NetsSynced,
	})

	for {
		netList = &networkv3.NetworkList{}
		netWatcher, err := w.client.Watch(context.Background(), netList, &client.ListOptions{})
		if err != nil {
			w.log.Errorf("couldn't watch networks: %s", err)
		}
		nadList = &netv1.NetworkAttachmentDefinitionList{}
		nadWatcher, err := w.client.Watch(context.Background(), nadList, &client.ListOptions{})
		if err != nil {
			w.log.Errorf("couldn't watch nads: %s", err)
		}
		w.watching(netWatcher, nadWatcher, t)
	}
}

func (w *NetWatcher) watching(netWatcher, nadWatcher watch.Interface, t *tomb.Tomb) bool {
	for {
		select {
		case <-t.Dying():
			w.log.Info("netwatcher dying")
			return true
		case update, ok := <-netWatcher.ResultChan():
			if !ok {
				w.log.Warn("network watch channel closed")
				return true
			}
			switch update.Type {
			case watch.Added:
				net := update.Object.(*networkv3.Network)
				err := w.OnNetAdded(net)
				if err != nil {
					w.log.Error(err)
				}
			case watch.Deleted:
				oldNet := update.Object.(*networkv3.Network)
				err := w.OnNetDeleted(oldNet.Name)
				if err != nil {
					w.log.Error(err)
				}
			case watch.Modified:
				w.log.Warn("network changed, not yet supported!")
			}
		case update, ok := <-nadWatcher.ResultChan():
			if !ok {
				w.log.Warn("nad watch channel closed")
			}
			switch update.Type {
			case watch.Added:
				nad := update.Object.(*netv1.NetworkAttachmentDefinition)
				err := w.onNadAdded(nad)
				if err != nil {
					w.log.Error(err)
				}
			case watch.Deleted:
				nad := update.Object.(*netv1.NetworkAttachmentDefinition)
				err := w.onNadDeleted(nad)
				if err != nil {
					w.log.Error(err)
				}
			}
		}
	}
}

func (w *NetWatcher) Stop() {
	close(w.stop)
}

func (w *NetWatcher) onNadDeleted(nad *netv1.NetworkAttachmentDefinition) error {
	delete(w.nads, nad.Namespace+"/"+nad.Name)
	for key, net := range w.networkDefinitions {
		if net.NetAttachDefs == nad.Namespace+"/"+nad.Name {
			w.networkDefinitions[key].NetAttachDefs = ""
			common.SendEvent(common.CalicoVppEvent{
				Type: common.NetAddedOrUpdated,
				New:  w.networkDefinitions[key],
			})
		}
	}
	return nil
}

func (w *NetWatcher) onNadAdded(nad *netv1.NetworkAttachmentDefinition) error {
	var nadConfig nadv1.NetConfList
	err := json.Unmarshal([]byte(nad.Spec.Config), &nadConfig)
	if err != nil {
		w.log.Error(err)
		return err
	}
	for _, plugin := range nadConfig.Plugins {
		for key, net := range w.networkDefinitions {
			if net.Name == plugin.DpOptions.NetName {
				w.nads[nad.Namespace+"/"+nad.Name] = net.Name
				w.networkDefinitions[key].NetAttachDefs = nad.Namespace + "/" + nad.Name
				common.SendEvent(common.CalicoVppEvent{
					Type: common.NetAddedOrUpdated,
					New:  w.networkDefinitions[key],
				})
			}
		}
	}
	return nil
}

func (w *NetWatcher) OnNetAdded(net *networkv3.Network) error {
	netDef, err := w.CreateVRFsForNet(net.Name, uint32(net.Spec.VNI), net.Spec.Range)
	if err != nil {
		return err
	}
	for nad, net := range w.nads {
		if net == netDef.Name {
			netDef.NetAttachDefs = nad
		}
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.NetAddedOrUpdated,
		New:  netDef,
	})
	return nil
}

func (w *NetWatcher) OnNetChanged(old, new *networkv3.Network) {
	// TODO handle network change
}

func (w *NetWatcher) OnNetDeleted(netName string) error {
	w.log.Infof("deleting network %s", netName)
	netDef, err := w.DeleteNetVRFs(netName)
	if err != nil {
		return err
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.NetDeleted,
		Old:  netDef,
	})
	return nil
}

func getNetworkVrfName(networkName string, suffix string) string {
	return fmt.Sprintf("pod-%s-table-%s", networkName, suffix)
}

func (w *NetWatcher) CreateVRFsForNet(networkName string, networkVni uint32, netRange string) (netDef *NetworkDefinition, err error) {
	/* Create and Setup the per-network VRF */
	var tables [2]uint32
	if _, ok := w.networkDefinitions[networkName]; ok {
		return w.networkDefinitions[networkName], nil
	}
	w.log.Infof("adding network %s", networkName)
	swIfIndex, err := w.vpp.CreateLoopback(common.ContainerSideMacAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "Error creating loopback for network")
	}
	w.log.Infof("loopback (sw %+v) added for network %s", swIfIndex, networkName)

	for idx, ipFamily := range vpplink.IpFamilies {
		vrfName := getNetworkVrfName(networkName, ipFamily.Str)
		vrfId, err := w.vpp.AllocateVRF(ipFamily.IsIp6, vrfName)
		w.log.Infof("Allocated %s VRF ID:%d", ipFamily.Str, vrfId)
		if err != nil {
			return nil, errors.Wrapf(err, "error allocating VRF %s", ipFamily.Str)
		}
		tables[idx] = vrfId
	}
	netDef = &NetworkDefinition{
		VRF:               VRF{Tables: tables},
		Vni:               uint32(networkVni),
		Name:              networkName,
		LoopbackSwIfIndex: swIfIndex,
		Range:             netRange}
	w.networkDefinitions[networkName] = netDef

	ip4, ip6 := w.GetNodeIPs()
	var ipaddrs = []*net.IP{ip4, ip6}
	for idx, ipFamily := range vpplink.IpFamilies {
		if ipaddrs[idx] != nil {
			err = w.vpp.SetInterfaceVRF(swIfIndex, netDef.VRF.Tables[idx], ipFamily.IsIp6)
			if err != nil {
				return nil, errors.Wrapf(err, "Error setting loopback %d in network vrf", swIfIndex)
			}
			err = w.vpp.AddInterfaceAddress(swIfIndex, common.ToMaxLenCIDR(*ipaddrs[idx]))
			if err != nil {
				return nil, errors.Wrapf(err, "Error adding address %s to pod loopback interface", *ipaddrs[idx])
			}
		}
	}
	return netDef, nil
}

func (w *NetWatcher) DeleteNetVRFs(networkName string) (*NetworkDefinition, error) {
	var err error
	if _, ok := w.networkDefinitions[networkName]; !ok {
		w.log.Errorf("non-existent network deleted: %s", networkName)
	}
	err = w.vpp.DeleteLoopback(w.networkDefinitions[networkName].LoopbackSwIfIndex)
	if err != nil {
		w.log.Errorf("Error deleting network Loopback %s", err)
	}
	w.log.Infof("loopback (sw %+v) deleted for network %s", w.networkDefinitions[networkName].LoopbackSwIfIndex, networkName)
	for idx, ipFamily := range vpplink.IpFamilies {
		vrfId := w.networkDefinitions[networkName].VRF.Tables[idx]
		w.log.Infof("Deleting VRF %d %s", vrfId, ipFamily.Str)
		err = w.vpp.DelVRF(vrfId, ipFamily.IsIp6)
		if err != nil {
			w.log.Errorf("Error deleting VRF %d %s : %s", vrfId, ipFamily.Str, err)
		}
	}
	netDef := w.networkDefinitions[networkName]
	delete(w.networkDefinitions, networkName)
	return netDef, nil
}

func (w *NetWatcher) GetNodeIPs() (ip4 *net.IP, ip6 *net.IP) {
	ip4, ip6 = common.GetBGPSpecAddresses(w.nodeBGPSpec)
	return ip4, ip6
}
