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
	AddServicePort(service *v1.Service, ep *v1.Endpoints, isNodePort bool) error
	DelServicePort(service *v1.Service, ep *v1.Endpoints, isNodePort bool) error
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
	ipv4             net.IP
	ipv6             net.IP
	lock             sync.Mutex
	vppTapSwIfindex  uint32
	serviceProvider  ServiceProvider
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
	swIfIndex, err := fetchVppTapSwifIndex()
	if err != nil {
		panic(err.Error())
	}
	node, err := calicoCliV3.Nodes().Get(context.Background(), config.NodeName, options.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	ipv4, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
	if err != nil {
		log.Infof("Node ipv4 parsing error %v", err)
	}
	ipv6, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
	if err != nil {
		log.Infof("Node ipv6 parsing error %v", err)
	}
	server := Server{
		clientv3:        calicoCliV3,
		vpp:             vpp,
		log:             log,
		vppTapSwIfindex: swIfIndex,
		ipv4:            ipv4,
		ipv6:            ipv6,
	}
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
		return s.ipv6
	} else {
		return s.ipv4
	}
}

func (s *Server) AddDelService(service *v1.Service, ep *v1.Endpoints, isWithdrawal bool) error {
	if s.serviceProvider == nil {
		return nil
	}
	isNodePort := false
	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		isNodePort = false
	case v1.ServiceTypeNodePort:
		isNodePort = true
	default:
		s.log.Debugf("service type creation not supported : %s", service.Spec.Type)
		return nil
	}
	if isWithdrawal {
		return s.serviceProvider.DelServicePort(service, ep, isNodePort)
	} else {
		return s.serviceProvider.AddServicePort(service, ep, isNodePort)
	}
}

func (s *Server) ConfigureSnat() (err error) {
	// Grab addresses from data interface
	var v4, v6 net.IP
	v4s, err := s.vpp.AddrList(config.DataInterfaceSwIfIndex, false)
	if err != nil {
		return errors.Wrap(err, "cannot list ipv4 on data itf")
	}
	if len(v4s) > 0 {
		v4 = v4s[0].IPNet.IP
	}
	if len(v4s) > 1 {
		s.log.Warnf("More than one v4 found on data interface: %v", v4s)
	}

	v6s, err := s.vpp.AddrList(config.DataInterfaceSwIfIndex, true)
	if err != nil {
		return errors.Wrap(err, "cannot list ipv6 on data itf")
	}
	v6set := false
	for _, a := range v6s {
		if a.IPNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if v6set {
			s.log.Warnf("More than one non-link-local v6 address found on data itf: %v", v6s)
			continue
		}
		v6 = a.IPNet.IP
		v6set = true
	}
	err = s.vpp.CalicoSetSnatAddresses(v4, v6)
	return errors.Wrapf(err, "Failed to configure SNAT addresses")
}

func (s *Server) OnVppRestart() {
	/* SNAT-outgoing config */
	err := s.ConfigureSnat()
	if err != nil {
		s.log.Errorf("Failed to reconfigure SNAT: %v", err)
	}

	/* Services NAT config */
	s.serviceProvider.OnVppRestart()
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
	err := s.AddDelService(service, ep, isWithdrawal)
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
	err := s.ConfigureSnat()
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
