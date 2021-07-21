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

package services

import (
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocliv3 "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"gopkg.in/tomb.v2"
)

type ServiceProvider interface {
	Init() error
	AddServicePort(service *v1.Service, ep *v1.Endpoints) error
	DelServicePort(service *v1.Service, ep *v1.Endpoints) error
	OnVppRestart()
}

type Server struct {
	*common.CalicoVppServerData
	log              *logrus.Entry
	vpp              *vpplink.VppLink
	t                tomb.Tomb
	endpointStore    cache.Store
	serviceStore     cache.Store
	serviceInformer  cache.Controller
	endpointInformer cache.Controller
	clientv3         calicocliv3.Interface
	client           *kubernetes.Clientset
	nodeIP4          net.IP
	nodeIP4Set       bool
	nodeIP6          net.IP
	nodeIP6Set       bool
	lock             sync.Mutex
	serviceProvider  ServiceProvider
}

func (s *Server) setSpecAddresses(nodeSpec *calicov3.NodeSpec) {
	if nodeSpec == nil {
		return
	} else if nodeSpec.BGP == nil {
		return
	}
	if nodeSpec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(nodeSpec.BGP.IPv4Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", nodeSpec.BGP.IPv4Address, err)
		} else {
			s.nodeIP4 = addr
			s.nodeIP4Set = true
		}
	}
	if nodeSpec.BGP.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(nodeSpec.BGP.IPv6Address)
		if err != nil {
			s.log.Errorf("cannot parse node address %s: %v", nodeSpec.BGP.IPv6Address, err)
		} else {
			s.nodeIP6 = addr
			s.nodeIP6Set = true
		}
	}
}

func NewServer(vpp *vpplink.VppLink, log *logrus.Entry) (*Server, error) {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		panic(err.Error())
	}
	calicoCliV3, err := calicocliv3.NewFromEnv()
	if err != nil {
		panic(err.Error())
	}
	server := Server{
		clientv3: calicoCliV3,
		client:   client,
		vpp:      vpp,
		log:      log,
	}
	node, err := calicoCliV3.Nodes().Get(context.Background(), config.NodeName, options.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	server.setSpecAddresses(&node.Spec)
	serviceListWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"services", "", fields.Everything())
	serviceStore, serviceInformer := cache.NewInformer(
		serviceListWatch,
		&v1.Service{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				server.handleServiceEndpointEvent(obj.(*v1.Service), nil, false)
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				server.handleServiceEndpointEvent(obj.(*v1.Service), nil, false)
			},
			DeleteFunc: func(obj interface{}) {
				server.handleServiceEndpointEvent(obj.(*v1.Service), nil, true)
			},
		})

	endpointListWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"endpoints", "", fields.Everything())
	endpointStore, endpointInformer := cache.NewInformer(
		endpointListWatch,
		&v1.Endpoints{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				server.handleServiceEndpointEvent(nil, obj.(*v1.Endpoints), false)
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				server.handleServiceEndpointEvent(nil, obj.(*v1.Endpoints), false)
			},
			DeleteFunc: func(obj interface{}) {
				server.handleServiceEndpointEvent(nil, obj.(*v1.Endpoints), true)
			},
		})

	server.endpointStore = endpointStore
	server.serviceStore = serviceStore
	server.serviceInformer = serviceInformer
	server.endpointInformer = endpointInformer

	if config.EnableServices {
		server.serviceProvider = newCalicoServiceProvider(&server)
	}
	return &server, nil
}

func (s *Server) getNodeIP(isv6 bool) net.IP {
	if isv6 {
		return s.nodeIP6
	} else {
		return s.nodeIP4
	}
}

func (s *Server) addDelService(service *v1.Service, ep *v1.Endpoints, isWithdrawal bool) error {
	if s.serviceProvider == nil {
		return nil
	}
	if isWithdrawal {
		return s.serviceProvider.DelServicePort(service, ep)
	} else {
		return s.serviceProvider.AddServicePort(service, ep)
	}
}

func (s *Server) configureSnat() (err error) {
	err = s.vpp.CnatSetSnatAddresses(s.nodeIP4, s.nodeIP6)
	if err != nil {
		s.log.Errorf("Failed to configure SNAT addresses %v", err)
	}
	if s.nodeIP6Set {
		err = s.vpp.CnatAddSnatPrefix(common.FullyQualified(s.nodeIP6))
		if err != nil {
			s.log.Errorf("Failed to add SNAT %s %v", common.FullyQualified(s.nodeIP6), err)
		}
	}
	if s.nodeIP4Set {
		err = s.vpp.CnatAddSnatPrefix(common.FullyQualified(s.nodeIP4))
		if err != nil {
			s.log.Errorf("Failed to add SNAT %s %v", common.FullyQualified(s.nodeIP4), err)
		}
	}
	for _, serviceCIDR := range config.ServiceCIDRs {
		err = s.vpp.CnatAddSnatPrefix(serviceCIDR)
		if err != nil {
			s.log.Errorf("Failed to Add Service CIDR %s %v", serviceCIDR, err)
		}
	}
	return nil
}

func (s *Server) OnVppRestart() {
	/* SNAT-outgoing config */
	err := s.configureSnat()
	if err != nil {
		s.log.Errorf("Failed to reconfigure SNAT: %v", err)
	}

	/* Services NAT config */
	if s.serviceProvider != nil {
		s.serviceProvider.OnVppRestart()
	}
}

func (s *Server) findMatchingService(ep *v1.Endpoints) *v1.Service {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ep)
	if err != nil {
		s.log.Errorf("Error getting endpoint %+v key: %v", ep, err)
		return nil
	}
	service, found, err := s.serviceStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting service %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Service %s not found", key)
		return nil
	}
	return service.(*v1.Service)
}

func (s *Server) findMatchingEndpoint(service *v1.Service) *v1.Endpoints {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(service)
	if err != nil {
		s.log.Errorf("Error getting service %+v key: %v", service, err)
		return nil
	}
	ep, found, err := s.endpointStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting endpoint %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Endpoint %s not found", key)
		return nil
	}
	return ep.(*v1.Endpoints)
}

func (s *Server) handleServiceEndpointEvent(service *v1.Service, ep *v1.Endpoints, isWithdrawal bool) {
	s.BarrierSync()
	s.lock.Lock()
	defer s.lock.Unlock()
	if service != nil && ep == nil {
		ep = s.findMatchingEndpoint(service)
	}
	if service == nil && ep != nil {
		service = s.findMatchingService(ep)
	}
	if ep == nil || service == nil {
		// Wait
		return
	}
	err := s.addDelService(service, ep, isWithdrawal)
	if err != nil {
		s.log.Errorf("Service errored %v", err)
	}
}

func (s *Server) Serve() {
	if s.serviceProvider != nil {
		err := s.serviceProvider.Init()
		if err != nil {
			s.log.Errorf("cannot init serviceProvider")
			s.log.Fatal(err)
		}
	}
	err := s.configureSnat()
	if err != nil {
		s.log.Errorf("Failed to configure SNAT: %v", err)
	}

	s.t.Go(func() error { s.serviceInformer.Run(s.t.Dying()); return nil })
	s.t.Go(func() error { s.endpointInformer.Run(s.t.Dying()); return nil })
	<-s.t.Dying()
}

func (s *Server) Stop() {
	s.t.Kill(errors.Errorf("GracefulStop"))
}
