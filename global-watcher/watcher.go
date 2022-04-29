// Copyright (C) 2019 Cisco Systems Inc.
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

package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	nadv1 "github.com/projectcalico/vpp-dataplane/global-watcher/networkAttachmentDefinition"
	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var log *logrus.Logger
var kubernetesClient client.WithWatch
var err error
var currentPodList map[string]*v1.Pod
var currentSvcList map[string]*v1.Service
var currentEpList map[string]*v1.Endpoints
var currentNadMap map[string]string

func main() {

	log = logrus.New()
	currentPodList = make(map[string]*v1.Pod)
	currentSvcList = make(map[string]*v1.Service)
	currentNadMap = make(map[string]string)
	currentEpList = make(map[string]*v1.Endpoints)
	GroupVersion := schema.GroupVersion{Group: "", Version: "v1"}
	SchemeBuilder := &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme := SchemeBuilder.AddToScheme
	SchemeBuilder.Register(&v1.ServiceList{}, &v1.PodList{}, &v1.Pod{}, &v1.Service{}, &v1.Endpoints{})

	k8sClient, err := watchers.NewClient(10*time.Second, []func(s *runtime.Scheme) error{AddToScheme, nadv1.AddToScheme})
	if err != nil {
		log.Errorf("failed instantiating kubernetes client: %v", err)
	}
	kubernetesClient = *k8sClient

restart:
	podList := &v1.PodList{}
	svcList := &v1.ServiceList{}
	nadList := &netv1.NetworkAttachmentDefinitionList{}

	podWatcher, err := kubernetesClient.Watch(context.Background(), podList, &client.ListOptions{})
	if err != nil {
		log.Errorf("couldn't watch pods: %s", err)
	}
	svcWatcher, err := kubernetesClient.Watch(context.Background(), svcList, &client.ListOptions{})
	if err != nil {
		log.Errorf("couldn't watch services: %s", err)
	}
	nadWatcher, err := kubernetesClient.Watch(context.Background(), nadList, &client.ListOptions{})
	if err != nil {
		log.Errorf("couldn't watch network attachment definitions: %s", err)
	}

	watching(podWatcher, svcWatcher, nadWatcher)
	goto restart
}

func watching(podWatcher, svcWatcher, nadWatcher watch.Interface) bool {
	for {
		select {
		case update, ok := <-nadWatcher.ResultChan():
			if !ok {
				log.Warn("network attachment definition watch channel closed")
				return true
			}
			switch update.Type {
			case watch.Added:
				nad := update.Object.(*netv1.NetworkAttachmentDefinition)
				var nadConfig nadv1.NetConfList
				err := json.Unmarshal([]byte(nad.Spec.Config), &nadConfig)
				if err != nil {
					log.Error(err)
				}
				for _, plugin := range nadConfig.Plugins {
					log.Infof("net attach def added %s: %s", plugin.DpOptions.NetName, nad.Name)
					currentNadMap[plugin.DpOptions.NetName] = nad.Name
				}
			case watch.Modified:
				log.Warn("net attach def modified: not supported")
			case watch.Deleted:
				nad := update.Object.(*netv1.NetworkAttachmentDefinition)
				var nadConfig nadv1.NetConfList
				err := json.Unmarshal([]byte(nad.Spec.Config), &nadConfig)
				if err != nil {
					log.Error(err)
				}
				for _, plugin := range nadConfig.Plugins {
					log.Infof("net attach def deleted %s: %s", plugin.DpOptions.NetName, nad.Name)
					delete(currentNadMap, plugin.DpOptions.NetName)
				}
			}
		case update, ok := <-podWatcher.ResultChan():
			if !ok {
				log.Warn("pods watch channel closed")
				return true
			}
			switch update.Type {
			case watch.Added:
				pod := update.Object.(*v1.Pod)
				podNadIf, inNetwork := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
				if inNetwork {
					podNad := podNadIf[0:strings.Index(podNadIf, "@")]
					log.Infof("POD (add) %s", pod.Name)
					currentPodList[pod.Name] = pod
					addPod(pod, podNad)
				}
			case watch.Deleted:
				pod := update.Object.(*v1.Pod)
				if _, found := currentPodList[pod.Name]; found {
					log.Infof("POD (del) %s", update.Object.(*v1.Pod).Name)
					delete(currentPodList, pod.Name)
					deletePod(pod)
				}
			}

		case update, ok := <-svcWatcher.ResultChan():
			if !ok {
				log.Warn("svc watch channel closed")
				return true
			}
			switch update.Type {
			case watch.Added:
				service := update.Object.(*v1.Service)
				if service.Spec.Selector == nil {
					selector, selectorFound := service.Annotations["extensions.projectcalico.org/selector"]
					network, networkFound := service.Annotations["extensions.projectcalico.org/network"]
					if selectorFound && networkFound {
						log.Infof("SVC (add) %s", service.Name)
						currentSvcList[service.Name] = service
						addService(update.Object.(*v1.Service), selector, network)
					}
				}
			case watch.Deleted:
				service := update.Object.(*v1.Service)
				if _, found := currentSvcList[service.Name]; found {
					log.Infof("SVC (del) %s", update.Object.(*v1.Service).Name)
					delete(currentSvcList, service.Name)
					delete(currentEpList, service.Name)
				}
			}
		}
	}
}

func addPod(pod *v1.Pod, podNad string) {
	for _, svc := range currentSvcList {
		svcSelector := svc.Annotations["extensions.projectcalico.org/selector"]
		svcNetwork := svc.Annotations["extensions.projectcalico.org/network"]
		svcSelectorLabels, err := labels.ConvertSelectorToLabelsMap(svcSelector)
		if err != nil {
			log.Error("selector annotation is not valid %s", err)
		} else {
			SelectorMatch := false
			for podSelectorKey, podSelectorValue := range pod.Labels {
				for svcSelectorKey, svcSelectorValue := range svcSelectorLabels {
					if podSelectorKey == svcSelectorKey && podSelectorValue == svcSelectorValue {
						SelectorMatch = true
					}
				}
			}
			svcNad, ok := currentNadMap[svcNetwork]
			if !ok {
				log.Errorf("net attach def does not exist for network %s", svcNetwork)
			} else if svcNad == podNad && SelectorMatch {
				updateEndpoint(pod, svc, svcNetwork)
			}
			err = kubernetesClient.Update(context.Background(), currentEpList[svc.Name])
			if err != nil {
				log.Error(err)
			}
		}
	}
}

func deletePod(pod *v1.Pod) {
	for name, ep := range currentEpList {
		newSubsetList := []v1.EndpointSubset{}
		for _, epSubset := range ep.Subsets {
			if epSubset.Addresses[0].TargetRef.Name != pod.Name { //all addresses of a subset should have same pod name
				newSubsetList = append(newSubsetList, epSubset)
			}
		}
		currentEpList[name].Subsets = newSubsetList
		err = kubernetesClient.Update(context.Background(), currentEpList[ep.Name])
		if err != nil {
			log.Error(err)
		}
	}

}

func addService(service *v1.Service, svcSelector string, svcNetwork string) {
	log.Info("Got request for network specific service")
	ep := createEndpointForService(service, svcNetwork)
	err := kubernetesClient.Create(context.Background(), ep)
	if err != nil {
		log.Error(err)
	}
	svcSelectorLabels, err := labels.ConvertSelectorToLabelsMap(svcSelector)
	if err != nil {
		log.Error("selector annotation is not valid %s", err)
	} else {
		for _, pod := range currentPodList {
			SelectorMatch := false
			for podSelectorKey, podSelectorValue := range pod.Labels {
				for svcSelectorKey, svcSelectorValue := range svcSelectorLabels {
					if podSelectorKey == svcSelectorKey && podSelectorValue == svcSelectorValue {
						SelectorMatch = true
					}
				}
			}
			podNadIf, podNetworkFound := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
			podNad := podNadIf[0:strings.Index(podNadIf, "@")]
			svcNad, ok := currentNadMap[svcNetwork]
			if !ok {
				log.Errorf("net attach def does not exist for network %s", svcNetwork)
			} else if podNetworkFound && svcNad == podNad && SelectorMatch {
				updateEndpoint(pod, service, svcNetwork)
			}
		}
	}
	err = kubernetesClient.Update(context.Background(), currentEpList[ep.Name])
	if err != nil {
		log.Error(err)
	}
}

func createEndpointForService(service *v1.Service, network string) (ep *v1.Endpoints) {
	ep = &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
	}
	currentEpList[ep.Name] = ep
	return
}

func updateEndpoint(pod *v1.Pod, service *v1.Service, network string) {
	epAddresses := []v1.EndpointAddress{}
	epPorts := []v1.EndpointPort{}
	podStatus := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace},
	}
retry: //need to re-get the pod because multus updates may take some time
	err := kubernetesClient.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, podStatus)
	if err != nil {
		log.Errorf("couldn't get pod: %s", err)
	}
	netStatusesJson, found := podStatus.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !found {
		log.Warn("no network status for pod, retrying...")
		time.Sleep(time.Second)
		goto retry
	} else {
		var netStatuses []nettypes.NetworkStatus
		err := json.Unmarshal([]byte(netStatusesJson), &netStatuses)
		if err != nil {
			log.Error(err)
		}
		for _, netStatus := range netStatuses {
			nad, ok := currentNadMap[network]
			if !ok {
				log.Errorf("net attach def does not exist for network %s", network)
			} else if strings.Contains(netStatus.Name, nad) {
				ips := netStatus.IPs
				for _, ip := range ips {
					epAddresses = append(epAddresses, v1.EndpointAddress{
						TargetRef: &v1.ObjectReference{
							Kind:      "pod",
							Namespace: "default",
							Name:      podStatus.Name,
						},
						IP:       ip,
						NodeName: &podStatus.Spec.NodeName,
					})
				}
			}
		}
	}
	for _, container := range podStatus.Spec.Containers {
		for _, containerPort := range container.Ports {
			epPorts = append(epPorts, v1.EndpointPort{
				Name:     containerPort.Name,
				Protocol: containerPort.Protocol,
				Port:     containerPort.ContainerPort})
		}
	}
	subset := v1.EndpointSubset{
		Addresses: epAddresses,
		Ports:     epPorts,
	}
	log.Infof("updating endpoint")
	if currentEpList[service.Name].Subsets == nil {
		currentEpList[service.Name].Subsets = []v1.EndpointSubset{subset}
	} else {
		currentEpList[service.Name].Subsets = append(currentEpList[service.Name].Subsets, subset)
	}
}
