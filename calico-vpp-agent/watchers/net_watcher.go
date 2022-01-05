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
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/api/pkg/client/informers_generated/externalversions"
	"github.com/sirupsen/logrus"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type VRF struct {
	tables [2]uint32 // one for ipv4, one for ipv6
}

type NetWatcher struct {
	log      *logrus.Entry
	client   *clientset.Clientset
	stop     chan struct{}
	factory  externalversions.SharedInformerFactory
	informer cache.SharedIndexInformer

	networkVRFs map[string]VRF
}

func NewNetWatcher(log *logrus.Entry) *NetWatcher {
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := clientset.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	factory := externalversions.NewSharedInformerFactory(client, 10*time.Minute)
	informer := factory.Projectcalico().V3().Networks().Informer()

	w := NetWatcher{
		log:      log,
		client:   client,
		stop:     make(chan struct{}),
		factory:  factory,
		informer: informer,
	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			net, ok := obj.(*v3.Network)
			if !ok {
				w.log.Errorf("Wrong object type received in network watcher: %v", obj)
			}
			w.OnNetAdded(net)
		},
		UpdateFunc: func(old, new interface{}) {
			oldNet, ok := old.(*v3.Network)
			if !ok {
				w.log.Errorf("Wrong object type received in network watcher: %v", old)
			}
			newNet, ok := new.(*v3.Network)
			if !ok {
				w.log.Errorf("Wrong object type received in network watcher: %v", new)
			}
			w.OnNetChanged(oldNet, newNet)
		},
		DeleteFunc: func(obj interface{}) {
			net, ok := obj.(*v3.Network)
			if !ok {
				w.log.Errorf("Wrong object type received in network watcher: %v", obj)
			}
			w.OnNetDeleted(net)
		},
	})

	return &w
}

func (w *NetWatcher) WatchNetworks() {
	w.informer.Run(w.stop)
}

func (w *NetWatcher) Stop() {
	close(w.stop)
}

func (w *NetWatcher) GetNetworkVRF(networkName string) (vrf VRF, found bool) {
	vrf, found = w.networkVRFs[networkName]
	return vrf, found
}

func (w *NetWatcher) OnNetAdded(net *v3.Network) {
	if _, ok := w.networkVRFs[net.Name]; ok {
		w.log.Errorf("existing network added: %s", net.Name)
	}
	w.CreateVRFsForNet(net.Name)
}

func (w *NetWatcher) OnNetChanged(old, new *v3.Network) {
	w.log.Infof("network %s changed", old.Name)
}

func (w *NetWatcher) OnNetDeleted(net *v3.Network) {
	if _, ok := w.networkVRFs[net.Name]; !ok {
		w.log.Errorf("non-existent network deleted: %s", net.Name)
	}
	w.DeleteNetVRFs(net.Name)
}

func (w *NetWatcher) CreateVRFsForNet(networkName string) {

}

func (w *NetWatcher) DeleteNetVRFs(networkName string) {

}
