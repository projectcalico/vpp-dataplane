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
	// VRF is the main table used for the corresponding physical network
	VRF VRF
	// PodVRF is the table used for the pods in the corresponding physical network
	PodVRF              VRF
	Vni                 uint32
	PhysicalNetworkName string
	Name                string
	Range               string
	NetAttachDefs       string
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

	currentWatchRevisionNet string
	currentWatchRevisionNad string
	NetWatcher              watch.Interface
	NadWatcher              watch.Interface
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

func (w *NetWatcher) cleanExistingWatchers() {
	for _, wat := range []watch.Interface{w.NetWatcher, w.NetWatcher} {
		if wat != nil {
			wat.Stop()
			w.log.Debug("Stopped watcher")
			wat = nil
		}
	}
}

func (w *NetWatcher) resyncAndCreateWatchers() error {
	if w.currentWatchRevisionNet == "" || w.currentWatchRevisionNad == "" {
		netList := &networkv3.NetworkList{}
		nadList := &netv1.NetworkAttachmentDefinitionList{}
		if w.currentWatchRevisionNet == "" {
			w.log.Debugf("Reconciliating Networks...")
			err := w.client.List(context.Background(), netList, &client.ListOptions{})
			if err != nil {
				return errors.Wrapf(err, "Listing Networks failed")
			}
			for _, net := range netList.Items {
				err := w.OnNetAdded(&net)
				if err != nil {
					return errors.Wrapf(err, "OnNetAdded failed for %v", net)
				}
			}
		}
		if w.currentWatchRevisionNad == "" {
			err := w.client.List(context.Background(), nadList, &client.ListOptions{})
			if err != nil {
				return errors.Wrapf(err, "Listing NetworkAttachmentDefinitions failed")
			}
			for _, nad := range nadList.Items {
				err = w.onNadAdded(&nad)
				if err != nil {
					return errors.Wrapf(err, "OnNadAdded failed for %v", nad)
				}
			}
		}
		w.InSync <- 1
		common.SendEvent(common.CalicoVppEvent{
			Type: common.NetsSynced,
		})
		w.currentWatchRevisionNet = netList.ResourceVersion
		w.currentWatchRevisionNad = nadList.ResourceVersion
	}
	w.cleanExistingWatchers()
	netList := &networkv3.NetworkList{}
	netWatcher, err := w.client.Watch(context.Background(), netList, &client.ListOptions{})
	if err != nil {
		w.log.Errorf("couldn't watch networks: %s", err)
	}
	nadList := &netv1.NetworkAttachmentDefinitionList{}
	nadWatcher, err := w.client.Watch(context.Background(), nadList, &client.ListOptions{})
	if err != nil {
		w.log.Errorf("couldn't watch nads: %s", err)
	}
	w.NetWatcher = netWatcher
	w.NadWatcher = nadWatcher
	return nil
}

func (w *NetWatcher) WatchNetworks(t *tomb.Tomb) error {
	w.log.Infof("Net watcher starts")

	for t.Alive() {
		w.currentWatchRevisionNet = ""
		w.currentWatchRevisionNad = ""
		err := w.resyncAndCreateWatchers()
		if err != nil {
			w.log.Error(err)
			goto restart
		}
		for {
			select {
			case <-t.Dying():
				w.log.Info("netwatcher dying")
				return nil
			case update, ok := <-w.NetWatcher.ResultChan():
				if !ok {
					err := w.resyncAndCreateWatchers()
					if err != nil {
						w.log.Error(err)
						goto restart
					}
					continue
				}
				switch update.Type {
				case watch.Added:
					net, ok := update.Object.(*networkv3.Network)
					if !ok {
						w.log.Errorf("update.Object is not *networkv3.Network, %v", net)
						continue
					}
					err := w.OnNetAdded(net)
					if err != nil {
						w.log.Error(err)
					}
				case watch.Deleted:
					oldNet, ok := update.Object.(*networkv3.Network)
					if !ok {
						w.log.Errorf("update.Object is not *networkv3.Network, %v", update.Object)
						continue
					}
					err := w.OnNetDeleted(oldNet.Name)
					if err != nil {
						w.log.Error(err)
					}
				case watch.Modified:
					w.log.Warn("network changed, not yet supported!")
				}
			case update, ok := <-w.NadWatcher.ResultChan():
				if !ok {
					err := w.resyncAndCreateWatchers()
					if err != nil {
						w.log.Error(err)
						goto restart
					}
					continue
				}
				switch update.Type {
				case watch.Added:
					nad, ok := update.Object.(*netv1.NetworkAttachmentDefinition)
					if !ok {
						w.log.Errorf("update.Object is not *NetworkAttachmentDefinition, %v", update.Object)
						continue
					}
					err := w.onNadAdded(nad)
					if err != nil {
						w.log.Error(err)
					}
				case watch.Deleted:
					nad, ok := update.Object.(*netv1.NetworkAttachmentDefinition)
					if !ok {
						w.log.Errorf("update.Object is not *NetworkAttachmentDefinition, %v", update.Object)
						continue
					}
					err := w.onNadDeleted(nad)
					if err != nil {
						w.log.Error(err)
					}
				}
			}
		}
	restart:
		w.log.Debug("restarting network watcher...")
		w.cleanExistingWatchers()
		time.Sleep(2 * time.Second)
	}
	w.log.Warn("Network watcher stopped")
	return nil
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
	if _, ok := common.VppManagerInfo.PhysicalNets[net.Spec.PhysicalNetworkName]; !ok {
		return errors.Errorf("physical network %s is not defined", net.Spec.PhysicalNetworkName)
	}
	netDef, err := w.CreateNetwork(net.Name, uint32(net.Spec.VNI), net.Spec.Range, net.Spec.PhysicalNetworkName)
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
	netDef, err := w.DeleteNetwork(netName)
	if err != nil {
		return err
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.NetDeleted,
		Old:  netDef,
	})
	return nil
}

func (w *NetWatcher) CreateNetwork(networkName string, networkVni uint32, netRange string, phyNet string) (netDef *NetworkDefinition, err error) {
	/* Create and Setup the per-network VRF */
	if _, ok := w.networkDefinitions[networkName]; ok {
		return w.networkDefinitions[networkName], nil
	}
	w.log.Infof("adding network %s", networkName)
	vrfID := common.VppManagerInfo.PhysicalNets[phyNet].VrfId
	podVrfID := common.VppManagerInfo.PhysicalNets[phyNet].PodVrfId
	netDef = &NetworkDefinition{
		VRF:                 VRF{Tables: [2]uint32{vrfID, vrfID}},
		PodVRF:              VRF{Tables: [2]uint32{podVrfID, podVrfID}},
		Vni:                 uint32(networkVni),
		PhysicalNetworkName: phyNet,
		Name:                networkName,
		Range:               netRange}
	w.networkDefinitions[networkName] = netDef
	return netDef, nil
}

func (w *NetWatcher) DeleteNetwork(networkName string) (*NetworkDefinition, error) {
	if _, ok := w.networkDefinitions[networkName]; !ok {
		return nil, errors.Errorf("non-existent network deleted: %s", networkName)
	}
	netDef := w.networkDefinitions[networkName]
	delete(w.networkDefinitions, networkName)
	return netDef, nil
}

func (w *NetWatcher) GetNodeIPs() (ip4 *net.IP, ip6 *net.IP) {
	ip4, ip6 = common.GetBGPSpecAddresses(w.nodeBGPSpec)
	return ip4, ip6
}
