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

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type Server struct {
	*common.CalicoVppServerData
	log              *logrus.Entry
	vpp              *vpplink.VppLink
	endpointStore    cache.Store
	serviceStore     cache.Store
	serviceInformer  cache.Controller
	endpointInformer cache.Controller

	lock sync.Mutex /* protects handleServiceEndpointEvent(s)/OnVppRestartServe */

	BGPConf     *calicov3.BGPConfigurationSpec
	nodeBGPSpec *oldv3.NodeBGPSpec

	stateMap map[string]*types.CnatTranslateEntry

	t tomb.Tomb
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.BGPConf = bgpConf
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *oldv3.NodeBGPSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func NewServiceServer(vpp *vpplink.VppLink, k8sclient *kubernetes.Clientset,
	log *logrus.Entry) *Server {
	server := Server{
		vpp:      vpp,
		log:      log,
		stateMap: make(map[string]*types.CnatTranslateEntry),
	}

	serviceListWatch := cache.NewListWatchFromClient(k8sclient.CoreV1().RESTClient(),
		"services", "", fields.Everything())
	serviceStore, serviceInformer := cache.NewInformer(
		serviceListWatch,
		&v1.Service{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				server.handleServiceEndpointEvent(obj.(*v1.Service), nil, nil, false)
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				server.handleServiceEndpointEvent(obj.(*v1.Service), old.(*v1.Service), nil, false)
			},
			DeleteFunc: func(obj interface{}) {
				svc, ok := obj.(*v1.Service)
				if !ok {
					svc = obj.(cache.DeletedFinalStateUnknown).Obj.(*v1.Service)
				}
				server.handleServiceEndpointEvent(svc, nil, nil, true)
			},
		})

	endpointListWatch := cache.NewListWatchFromClient(k8sclient.CoreV1().RESTClient(),
		"endpoints", "", fields.Everything())
	endpointStore, endpointInformer := cache.NewInformer(
		endpointListWatch,
		&v1.Endpoints{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				server.handleServiceEndpointEvent(nil, nil, obj.(*v1.Endpoints), false)
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				server.handleServiceEndpointEvent(nil, nil, obj.(*v1.Endpoints), false)
			},
			DeleteFunc: func(obj interface{}) {
				ep, ok := obj.(*v1.Endpoints)
				if !ok {
					ep = obj.(cache.DeletedFinalStateUnknown).Obj.(*v1.Endpoints)
				}
				server.handleServiceEndpointEvent(nil, nil, ep, true)
			},
		})

	server.endpointStore = endpointStore
	server.serviceStore = serviceStore
	server.serviceInformer = serviceInformer
	server.endpointInformer = endpointInformer

	return &server
}

func (s *Server) getNodeIP(isv6 bool) net.IP {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	if isv6 {
		if nodeIP6 != nil {
			return *nodeIP6
		}
	} else {
		if nodeIP4 != nil {
			return *nodeIP4
		}
	}
	return net.IP{}
}

func (s *Server) addDelService(service *v1.Service, ep *v1.Endpoints, isWithdrawal bool) error {
	if !config.EnableServices {
		return nil
	}
	if isWithdrawal {
		return s.delServicePort(service, ep)
	} else {
		return s.addServicePort(service, ep)
	}
}

func (s *Server) configureSnat() (err error) {
	err = s.vpp.CnatSetSnatAddresses(s.getNodeIP(false /* isv6 */), s.getNodeIP(true /* isv6 */))
	if err != nil {
		s.log.Errorf("Failed to configure SNAT addresses %v", err)
	}
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.nodeBGPSpec)
	if nodeIP6 != nil {
		err = s.vpp.CnatAddSnatPrefix(common.FullyQualified(*nodeIP6))
		if err != nil {
			s.log.Errorf("Failed to add SNAT %s %v", common.FullyQualified(*nodeIP6), err)
		}
	}
	if nodeIP4 != nil {
		err = s.vpp.CnatAddSnatPrefix(common.FullyQualified(*nodeIP4))
		if err != nil {
			s.log.Errorf("Failed to add SNAT %s %v", common.FullyQualified(*nodeIP4), err)
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
	if config.EnableServices {
		s.lock.Lock()
		defer s.lock.Unlock()
		newState := make(map[string]*types.CnatTranslateEntry)
		for key, entry := range s.stateMap {
			entryID, err := s.vpp.CnatTranslateAdd(entry)
			if err != nil {
				s.log.Errorf("Error re-injecting cnat entry %s : %v", entry.String(), err)
			} else {
				entry.ID = entryID
				newState[key] = entry
			}
		}
		s.stateMap = newState
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

func differentIPList(list1 []string, list2 []string) bool {
	if len(list1) != len(list2) {
		return true
	}
	for i, v := range list1 {
		if v != list2[i] {
			return true
		}
	}
	return false
}

func differentIPServices(service1 *v1.Service, service2 *v1.Service) bool {
	if service1.Spec.ClusterIP != service2.Spec.ClusterIP {
		return true
	}
	if service1.Spec.LoadBalancerIP != service2.Spec.LoadBalancerIP {
		return true
	}
	if differentIPList(service1.Spec.ExternalIPs, service2.Spec.ExternalIPs) {
		return true
	}
	if differentIPList(service1.Spec.ClusterIPs, service2.Spec.ClusterIPs) {
		return true
	}
	return false
}

func (s *Server) handleServiceEndpointEvent(service *v1.Service, oldService *v1.Service, ep *v1.Endpoints, isWithdrawal bool) {
	common.WaitIfVppIsRestarting()

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
	if oldService != nil {
		if differentIPServices(oldService, service) {
			err := s.addDelService(oldService, ep, true)
			if err != nil {
				s.log.Errorf("Service errored %v", err)
			}
		}
	}
	err := s.addDelService(service, ep, isWithdrawal)
	if err != nil {
		s.log.Errorf("Service errored %v", err)
	}
}

func (s *Server) getServiceIPs() ([]*net.IPNet, []*net.IPNet, []*net.IPNet) {
	var serviceClusterIPNets []*net.IPNet
	var serviceExternalIPNets []*net.IPNet
	var serviceLBIPNets []*net.IPNet
	for _, serviceClusterIP := range s.BGPConf.ServiceClusterIPs {
		_, netIP, err := net.ParseCIDR(serviceClusterIP.CIDR)
		if err != nil {
			s.log.Error(err)
			continue
		}
		serviceClusterIPNets = append(serviceClusterIPNets, netIP)
	}
	for _, serviceExternalIP := range s.BGPConf.ServiceExternalIPs {
		_, netIP, err := net.ParseCIDR(serviceExternalIP.CIDR)
		if err != nil {
			s.log.Error(err)
			continue
		}
		serviceExternalIPNets = append(serviceExternalIPNets, netIP)
	}
	for _, serviceLBIP := range s.BGPConf.ServiceLoadBalancerIPs {
		_, netIP, err := net.ParseCIDR(serviceLBIP.CIDR)
		if err != nil {
			s.log.Error(err)
			continue
		}
		serviceLBIPNets = append(serviceLBIPNets, netIP)
	}

	return serviceClusterIPNets, serviceExternalIPNets, serviceLBIPNets
}

func (s *Server) ServeService(t *tomb.Tomb) error {
	err := s.configureSnat()
	if err != nil {
		s.log.Errorf("Failed to configure SNAT: %v", err)
	}
	serviceClusterIPNets, serviceExternalIPNets, serviceLBIPNets := s.getServiceIPs()
	for _, serviceIPNet := range append(serviceClusterIPNets, append(serviceExternalIPNets, serviceLBIPNets...)...) {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.LocalPodAddressAdded,
			New:  serviceIPNet,
		})
	}

	s.t.Go(func() error { s.serviceInformer.Run(t.Dying()); return nil })
	s.t.Go(func() error { s.endpointInformer.Run(t.Dying()); return nil })

	<-s.t.Dying()

	s.log.Infof("Service Server returned")

	return nil
}
