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

package watchers

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
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

	endpointStore    cache.Store
	serviceStore     cache.Store
	serviceInformer  cache.Controller
	endpointInformer cache.Controller

	t tomb.Tomb
}

func (s *Server) resolveLocalServiceFromService(service *v1.Service) *common.ServiceAndEndpoints {
	if service == nil {
		return nil
	}
	ep := s.findMatchingEndpoint(service)
	if ep == nil {
		s.log.Debugf("svc() no endpoints found for service=%s", services.ServiceID(&service.ObjectMeta))
		return nil
	}
	return &common.ServiceAndEndpoints{
		Service:   service,
		Endpoints: ep,
	}
}

func (s *Server) resolveLocalServiceFromEndpoints(ep *v1.Endpoints) *common.ServiceAndEndpoints {
	if ep == nil {
		return nil
	}
	service := s.findMatchingService(ep)
	if service == nil {
		s.log.Debugf("svc() no svc found for endpoints=%s", services.ServiceID(&ep.ObjectMeta))
		return nil
	}
	return &common.ServiceAndEndpoints{
		Service:   service,
		Endpoints: ep,
	}
}

func NewServiceServer(eventChan chan any, k8sclient *kubernetes.Clientset, log *logrus.Entry) *Server {
	server := &Server{
		log:       log,
		eventChan: eventChan,
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

	endpointStore, endpointInformer := cache.NewInformerWithOptions(
		cache.InformerOptions{
			ListerWatcher: cache.NewListWatchFromClient(
				k8sclient.CoreV1().RESTClient(),
				"endpoints",
				"",
				fields.Everything(),
			),
			ObjectType:   &v1.Endpoints{},
			ResyncPeriod: 60 * time.Second,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					endpoints, ok := obj.(*v1.Endpoints)
					if !ok {
						panic("wrong type for obj, not *v1.Endpoints")
					}
					eventChan <- &common.ServiceEndpointsUpdate{
						New: server.resolveLocalServiceFromEndpoints(endpoints),
					}
				},
				UpdateFunc: func(old interface{}, obj interface{}) {
					endpoints, ok := obj.(*v1.Endpoints)
					if !ok {
						panic("wrong type for obj, not *v1.Endpoints")
					}
					oldEndpoints, ok := old.(*v1.Endpoints)
					if !ok {
						panic("wrong type for old, not *v1.Endpoints")
					}
					eventChan <- &common.ServiceEndpointsUpdate{
						New: server.resolveLocalServiceFromEndpoints(endpoints),
						Old: server.resolveLocalServiceFromEndpoints(oldEndpoints),
					}
				},
				DeleteFunc: func(obj interface{}) {
					switch value := obj.(type) {
					case cache.DeletedFinalStateUnknown:
						endpoints, ok := value.Obj.(*v1.Endpoints)
						if !ok {
							panic(fmt.Sprintf("obj.(cache.DeletedFinalStateUnknown).Obj not a (*v1.Endpoints) %v", obj))
						}
						eventChan <- &common.ServiceEndpointsDelete{
							Meta: &endpoints.ObjectMeta,
						}
					case *v1.Endpoints:
						eventChan <- &common.ServiceEndpointsDelete{
							Meta: &value.ObjectMeta,
						}
					default:
						log.Errorf("unknown type in endpoints deleteFunction %v", obj)
					}
				},
			},
		},
	)

	server.endpointStore = endpointStore
	server.serviceStore = serviceStore
	server.serviceInformer = serviceInformer
	server.endpointInformer = endpointInformer
	return server
}

func (s *Server) findMatchingService(ep *v1.Endpoints) *v1.Service {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ep)
	if err != nil {
		s.log.Errorf("Error getting endpoint %+v key: %v", ep, err)
		return nil
	}
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

func (s *Server) findMatchingEndpoint(service *v1.Service) *v1.Endpoints {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(service)
	if err != nil {
		s.log.Errorf("Error getting service %+v key: %v", service, err)
		return nil
	}
	value, found, err := s.endpointStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting endpoint %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Endpoint %s not found", key)
		return nil
	}
	endpoints, ok := value.(*v1.Endpoints)
	if !ok {
		panic("s.serviceStore.GetByKey did not return value of type *v1.Service")
	}
	return endpoints
}

func (s *Server) ServeService(t *tomb.Tomb) error {
	if *config.GetCalicoVppDebug().ServicesEnabled {
		s.t.Go(func() error { s.serviceInformer.Run(t.Dying()); return nil })
		s.t.Go(func() error { s.endpointInformer.Run(t.Dying()); return nil })
	}

	<-s.t.Dying()
	s.log.Warn("Service Server returned")
	return nil
}
