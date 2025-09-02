// Copyright (C) 2026 Cisco Systems Inc.
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
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/services"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type Server struct {
	log       *logrus.Entry
	eventChan chan any

	endpointSlicesStore    cache.Store
	serviceStore           cache.Store
	serviceInformer        cache.Controller
	endpointSlicesInformer cache.Controller

	endpointSlicesByService map[string]map[string]*discoveryv1.EndpointSlice
	endpointSlices          map[string]*discoveryv1.EndpointSlice

	t tomb.Tomb
}

func cloneEndpointSliceMap(epSlices map[string]*discoveryv1.EndpointSlice) map[string]*discoveryv1.EndpointSlice {
	if len(epSlices) == 0 {
		return nil
	}
	clone := make(map[string]*discoveryv1.EndpointSlice, len(epSlices))
	for key, epSlice := range epSlices {
		clone[key] = epSlice
	}
	return clone
}

func serviceName(es *discoveryv1.EndpointSlice) string {
	return es.Namespace + "/" + es.Labels[discoveryv1.LabelServiceName]
}

func objectID(meta *metav1.ObjectMeta) string {
	return meta.Namespace + "/" + meta.Name
}

func (s *Server) resolveLocalServiceFromService(service *v1.Service) *common.ServiceAndEndpoints {
	if service == nil {
		return nil
	}
	return &common.ServiceAndEndpoints{
		Service:        service,
		EndpointSlices: cloneEndpointSliceMap(s.endpointSlicesByService[services.ServiceID(&service.ObjectMeta)]),
	}
}

func (s *Server) resolveLocalServiceFromEndpointSlices(svcKey string) *common.ServiceAndEndpoints {
	service := s.findMatchingService(svcKey)
	if service == nil {
		s.log.Debugf("svc() no svc found for endpointslices=%s", svcKey)
		return nil
	}
	return &common.ServiceAndEndpoints{
		Service:        service,
		EndpointSlices: cloneEndpointSliceMap(s.endpointSlicesByService[svcKey]),
	}
}

func NewServiceServer(eventChan chan any, k8sclient *kubernetes.Clientset, log *logrus.Entry) *Server {
	server := &Server{
		log:                     log,
		eventChan:               eventChan,
		endpointSlicesByService: make(map[string]map[string]*discoveryv1.EndpointSlice),
		endpointSlices:          make(map[string]*discoveryv1.EndpointSlice),
	}
	serviceStore, serviceInformer := cache.NewInformerWithOptions(
		cache.InformerOptions{
			ListerWatcher: cache.NewListWatchFromClient(
				k8sclient.CoreV1().RESTClient(),
				"services",
				"",
				fields.Everything(),
			),
			ObjectType:   &v1.Service{},
			ResyncPeriod: 60 * time.Second,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					service, ok := obj.(*v1.Service)
					if !ok {
						panic("wrong type for obj, not *v1.Service")
					}
					eventChan <- &common.ServiceEndpointsUpdate{
						New: server.resolveLocalServiceFromService(service),
					}
				},
				UpdateFunc: func(old interface{}, obj interface{}) {
					service, ok := obj.(*v1.Service)
					if !ok {
						panic("wrong type for obj, not *v1.Service")
					}
					oldService, ok := old.(*v1.Service)
					if !ok {
						panic("wrong type for old, not *v1.Service")
					}
					eventChan <- &common.ServiceEndpointsUpdate{
						Old: server.resolveLocalServiceFromService(oldService),
						New: server.resolveLocalServiceFromService(service),
					}
				},
				DeleteFunc: func(obj interface{}) {
					switch value := obj.(type) {
					case cache.DeletedFinalStateUnknown:
						service, ok := value.Obj.(*v1.Service)
						if !ok {
							panic(fmt.Sprintf("obj.(cache.DeletedFinalStateUnknown).Obj not a (*v1.Service) %v", obj))
						}
						eventChan <- &common.ServiceEndpointsDelete{
							Meta: &service.ObjectMeta,
						}
					case *v1.Service:
						eventChan <- &common.ServiceEndpointsDelete{
							Meta: &value.ObjectMeta,
						}
					default:
						log.Errorf("unknown type in service deleteFunction %v", obj)
					}
				},
			},
		},
	)

	endpointSlicesStore, endpointSlicesInformer := cache.NewInformerWithOptions(
		cache.InformerOptions{
			ListerWatcher: cache.NewListWatchFromClient(
				k8sclient.DiscoveryV1().RESTClient(),
				"endpointslices",
				"",
				fields.Everything(),
			),
			ObjectType:   &discoveryv1.EndpointSlice{},
			ResyncPeriod: 60 * time.Second,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					epSlice, ok := obj.(*discoveryv1.EndpointSlice)
					if !ok {
						panic("wrong type for obj, not *discoveryv1.EndpointSlice")
					}
					svcKey := serviceName(epSlice)
					oldLocalService := server.resolveLocalServiceFromEndpointSlices(svcKey)
					if len(server.endpointSlicesByService[svcKey]) == 0 {
						server.endpointSlicesByService[svcKey] = make(map[string]*discoveryv1.EndpointSlice)
					}
					server.endpointSlicesByService[svcKey][objectID(&epSlice.ObjectMeta)] = epSlice
					server.endpointSlices[objectID(&epSlice.ObjectMeta)] = epSlice
					eventChan <- &common.ServiceEndpointsUpdate{
						Old: oldLocalService,
						New: server.resolveLocalServiceFromEndpointSlices(svcKey),
					}
				},
				UpdateFunc: func(old interface{}, obj interface{}) {
					epSlice, ok := obj.(*discoveryv1.EndpointSlice)
					if !ok {
						panic("wrong type for obj, not *discoveryv1.EndpointSlice")
					}
					svcKey := serviceName(epSlice)
					oldLocalService := server.resolveLocalServiceFromEndpointSlices(svcKey)
					if len(server.endpointSlicesByService[svcKey]) == 0 {
						server.endpointSlicesByService[svcKey] = make(map[string]*discoveryv1.EndpointSlice)
					}
					server.endpointSlicesByService[svcKey][objectID(&epSlice.ObjectMeta)] = epSlice
					server.endpointSlices[objectID(&epSlice.ObjectMeta)] = epSlice
					eventChan <- &common.ServiceEndpointsUpdate{
						Old: oldLocalService,
						New: server.resolveLocalServiceFromEndpointSlices(svcKey),
					}
				},
				DeleteFunc: func(obj interface{}) {
					key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
					if err != nil {
						panic("wrong type for obj, could not get DeletionHandlingMetaNamespaceKeyFunc")
					}
					epSlice, found := server.endpointSlices[key]
					if !found {
						switch value := obj.(type) {
						case cache.DeletedFinalStateUnknown:
							epSlice, _ = value.Obj.(*discoveryv1.EndpointSlice)
						case *discoveryv1.EndpointSlice:
							epSlice = value
						}
					}
					if epSlice == nil {
						log.Debugf("endpointslice %s not found in map", key)
						return
					}
					svcKey := serviceName(epSlice)
					oldLocalService := server.resolveLocalServiceFromEndpointSlices(svcKey)
					delete(server.endpointSlicesByService[svcKey], objectID(&epSlice.ObjectMeta))
					if len(server.endpointSlicesByService[svcKey]) == 0 {
						delete(server.endpointSlicesByService, svcKey)
					}
					delete(server.endpointSlices, key)
					eventChan <- &common.ServiceEndpointsUpdate{
						Old: oldLocalService,
						New: server.resolveLocalServiceFromEndpointSlices(svcKey),
					}
				},
			},
		},
	)

	server.endpointSlicesStore = endpointSlicesStore
	server.serviceStore = serviceStore
	server.serviceInformer = serviceInformer
	server.endpointSlicesInformer = endpointSlicesInformer
	return server
}

func (s *Server) findMatchingService(key string) *v1.Service {
	value, found, err := s.serviceStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting service %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Service %s not found", key)
		return nil
	}
	service, ok := value.(*v1.Service)
	if !ok {
		panic("s.serviceStore.GetByKey did not return value of type *v1.Service")
	}
	return service
}

func (s *Server) ServeService(t *tomb.Tomb) error {
	if *config.GetCalicoVppDebug().ServicesEnabled {
		s.t.Go(func() error { s.serviceInformer.Run(t.Dying()); return nil })
		s.t.Go(func() error { s.endpointSlicesInformer.Run(t.Dying()); return nil })
	}

	<-s.t.Dying()
	s.log.Warn("Service Server returned")
	return nil
}
