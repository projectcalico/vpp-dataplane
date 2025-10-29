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

	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	nadv1 "github.com/projectcalico/vpp-dataplane/v3/multinet-monitor/multinettypes"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var log *logrus.Logger
var kubernetesClient client.WithWatch
var err error
var currentPodList map[string]*v1.Pod
var currentSvcList map[string]*v1.Service
var currentEpSliceList map[string]*discoveryv1.EndpointSlice
var currentNadMap map[string]string

func main() {

	log = logrus.New()
	currentPodList = make(map[string]*v1.Pod)
	currentSvcList = make(map[string]*v1.Service)
	currentNadMap = make(map[string]string)
	currentEpSliceList = make(map[string]*discoveryv1.EndpointSlice)
	GroupVersion := schema.GroupVersion{Group: "", Version: "v1"}
	SchemeBuilder := &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme := SchemeBuilder.AddToScheme
	SchemeBuilder.Register(&v1.ServiceList{}, &v1.PodList{}, &v1.Pod{}, &v1.Service{}, &discoveryv1.EndpointSlice{})

	k8sClient, err := watchers.NewK8SClient(10*time.Second, []func(s *runtime.Scheme) error{AddToScheme, nadv1.AddToScheme})
	if err != nil {
		log.Errorf("failed instantiating kubernetes client: %v", err)
	}
	kubernetesClient = *k8sClient

	for {
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
			log.Errorf("Network attachment definition CRD probably needs to be installed")
			return
		}

		watching(podWatcher, svcWatcher, nadWatcher)
	}
}

func watching(podWatcher, svcWatcher, nadWatcher watch.Interface) {
	for {
		select {
		case update, ok := <-nadWatcher.ResultChan():
			if !ok {
				log.Warn("network attachment definition watch channel closed")
				return
			}
			switch update.Type {
			case watch.Added:
				nad, ok := update.Object.(*netv1.NetworkAttachmentDefinition)
				if !ok {
					log.Errorf("update.Object is not a (*netv1.NetworkAttachmentDefinition), %v", update.Object)
					continue
				}
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
				nad, ok := update.Object.(*netv1.NetworkAttachmentDefinition)
				if !ok {
					log.Errorf("update.Object is not a (*netv1.NetworkAttachmentDefinition), %v", update.Object)
					continue
				}
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
				return
			}
			switch update.Type {
			case watch.Added:
				pod, ok := update.Object.(*v1.Pod)
				if !ok {
					log.Errorf("update.Object is not a (*v1.Pod), %v", update.Object)
					continue
				}
				podNadIf, inNetwork := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
				if inNetwork {
					podNad := strings.Split(podNadIf, "@")[0]
					log.Infof("POD (add) %s", pod.Name)
					currentPodList[pod.Name] = pod
					addPod(pod, podNad)
				}
			case watch.Deleted:
				pod, ok := update.Object.(*v1.Pod)
				if !ok {
					log.Errorf("update.Object is not a (*v1.Pod), %v", update.Object)
					continue
				}
				if _, found := currentPodList[pod.Name]; found {
					log.Infof("POD (del) %s", pod.Name)
					delete(currentPodList, pod.Name)
					deletePod(pod)
				}
			}

		case update, ok := <-svcWatcher.ResultChan():
			if !ok {
				log.Warn("svc watch channel closed")
				return
			}
			switch update.Type {
			case watch.Added:
				service, ok := update.Object.(*v1.Service)
				if !ok {
					log.Errorf("update.Object is not a (*v1.Service), %v", update.Object)
					continue
				}
				if service.Spec.Selector == nil {
					selector, selectorFound := service.Annotations["extensions.projectcalico.org/selector"]
					network, networkFound := service.Annotations["extensions.projectcalico.org/network"]
					if selectorFound && networkFound {
						log.Infof("SVC (add) %s", service.Name)
						currentSvcList[service.Name] = service
						addService(service, selector, network)
					}
				}
			case watch.Deleted:
				service, ok := update.Object.(*v1.Service)
				if !ok {
					log.Errorf("update.Object is not a (*v1.Service), %v", update.Object)
					continue
				}
				if _, found := currentSvcList[service.Name]; found {
					log.Infof("SVC (del) %s", service.Name)
					delete(currentSvcList, service.Name)
					delete(currentEpSliceList, service.Name)
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
			log.Errorf("selector annotation is not valid %s", err)
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
			if eps, exists := currentEpSliceList[svc.Name]; exists {
				err = kubernetesClient.Update(context.Background(), eps)
				if err != nil {
					log.Error(err)
				}
			}
		}
	}
}

func deletePod(pod *v1.Pod) {
	for name, eps := range currentEpSliceList {
		newEndpoints := []discoveryv1.Endpoint{}
		for _, endpoint := range eps.Endpoints {
			if endpoint.TargetRef != nil && endpoint.TargetRef.Name != pod.Name {
				newEndpoints = append(newEndpoints, endpoint)
			}
		}
		currentEpSliceList[name].Endpoints = newEndpoints
		err = kubernetesClient.Update(context.Background(), currentEpSliceList[name])
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
		log.Errorf("selector annotation is not valid %s", err)
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
	err = kubernetesClient.Update(context.Background(), currentEpSliceList[ep.Name])
	if err != nil {
		log.Error(err)
	}
}

func createEndpointForService(service *v1.Service, network string) (ep *discoveryv1.EndpointSlice) {
	ep = &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.Name,
			Namespace: service.Namespace,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: service.Name,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	currentEpSliceList[ep.Name] = ep
	return
}

func updateEndpoint(pod *v1.Pod, service *v1.Service, network string) {
	var epAddresses []string
	epPorts := []discoveryv1.EndpointPort{}
	podStatus := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace},
	}
retry: // need to re-get the pod because multus updates may take some time
	err := kubernetesClient.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, podStatus)
	if err != nil {
		log.Errorf("couldn't get pod: %s", err)
	}
	netStatusesJSON, found := podStatus.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !found {
		log.Warn("no network status for pod, retrying...")
		time.Sleep(time.Second)
		goto retry
	} else {
		var netStatuses []netv1.NetworkStatus
		err := json.Unmarshal([]byte(netStatusesJSON), &netStatuses)
		if err != nil {
			log.Error(err)
		}
		for _, netStatus := range netStatuses {
			nad, ok := currentNadMap[network]
			if !ok {
				log.Errorf("net attach def does not exist for network %s", network)
			} else if strings.Contains(netStatus.Name, nad) {
				ips := netStatus.IPs
				epAddresses = append(epAddresses, ips...)
			}
		}
	}
	for _, container := range podStatus.Spec.Containers {
		for _, containerPort := range container.Ports {
			portName := containerPort.Name
			epPorts = append(epPorts, discoveryv1.EndpointPort{
				Name:     &portName,
				Protocol: &containerPort.Protocol,
				Port:     &containerPort.ContainerPort})
		}
	}
	endpoint := discoveryv1.Endpoint{
		Addresses: epAddresses,
		TargetRef: &v1.ObjectReference{
			Kind:      "Pod",
			Namespace: podStatus.Namespace,
			Name:      podStatus.Name,
		},
		NodeName: ptr.To(podStatus.Spec.NodeName),
	}
	log.Infof("updating endpoint")
	if currentEpSliceList[service.Name].Endpoints == nil {
		currentEpSliceList[service.Name].Endpoints = []discoveryv1.Endpoint{endpoint}
	} else {
		currentEpSliceList[service.Name].Endpoints = append(currentEpSliceList[service.Name].Endpoints, endpoint)
	}
	currentEpSliceList[service.Name].Ports = epPorts
}
