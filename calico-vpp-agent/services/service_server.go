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
	"fmt"
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

type CnatTranslateEntryVPPState struct {
	Entry          types.CnatTranslateEntry
	OwnerServiceID string
}

type LocalService struct {
	Entries        []CnatTranslateEntryVPPState
	SpecificRoutes []net.IP
}

func (es *CnatTranslateEntryVPPState) Key() string {
	return fmt.Sprintf("%s#%s#%d", es.Entry.Proto.String(), es.Entry.Endpoint.IP, es.Entry.Endpoint.Port)
}

func (es *CnatTranslateEntryVPPState) String() string {
	return fmt.Sprintf("svcID=%s %s", es.OwnerServiceID, es.Entry.String())
}

type Server struct {
	log              *logrus.Entry
	vpp              *vpplink.VppLink
	endpointStore    cache.Store
	serviceStore     cache.Store
	serviceInformer  cache.Controller
	endpointInformer cache.Controller

	lock sync.Mutex /* protects handleServiceEndpointEvent(s)/Serve */

	BGPConf     *calicov3.BGPConfigurationSpec
	nodeBGPSpec *oldv3.NodeBGPSpec

	stateMap map[string]CnatTranslateEntryVPPState

	t tomb.Tomb
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.BGPConf = bgpConf
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *oldv3.NodeBGPSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func (s *Server) resolveLocalServiceFromService(service *v1.Service) *LocalService {
	if service == nil {
		return nil
	}
	ep := s.findMatchingEndpoint(service)
	if ep == nil {
		return nil
	}
	return s.GetLocalService(service, ep)
}

func (s *Server) resolveLocalServiceFromEndpoints(ep *v1.Endpoints) *LocalService {
	if ep == nil {
		return nil
	}
	service := s.findMatchingService(ep)
	if service == nil {
		return nil
	}
	return s.GetLocalService(service, ep)
}

func NewServiceServer(vpp *vpplink.VppLink, k8sclient *kubernetes.Clientset, log *logrus.Entry) *Server {
	server := Server{
		vpp:      vpp,
		log:      log,
		stateMap: make(map[string]CnatTranslateEntryVPPState),
	}

	serviceListWatch := cache.NewListWatchFromClient(k8sclient.CoreV1().RESTClient(),
		"services", "", fields.Everything())
	serviceStore, serviceInformer := cache.NewInformer(
		serviceListWatch,
		&v1.Service{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				localService := server.resolveLocalServiceFromService(obj.(*v1.Service))
				server.handleServiceEndpointEvent(localService, nil)
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				oldLocalService := server.resolveLocalServiceFromService(old.(*v1.Service))
				localService := server.resolveLocalServiceFromService(obj.(*v1.Service))
				server.handleServiceEndpointEvent(localService, oldLocalService)
			},
			DeleteFunc: func(obj interface{}) {
				service, ok := obj.(*v1.Service)
				if !ok {
					service = obj.(cache.DeletedFinalStateUnknown).Obj.(*v1.Service)
				}
				oldLocalService := server.resolveLocalServiceFromService(service)
				server.handleServiceEndpointEvent(nil, oldLocalService)
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
				localService := server.resolveLocalServiceFromEndpoints(obj.(*v1.Endpoints))
				server.handleServiceEndpointEvent(localService, nil)
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				oldLocalService := server.resolveLocalServiceFromEndpoints(old.(*v1.Endpoints))
				localService := server.resolveLocalServiceFromEndpoints(obj.(*v1.Endpoints))
				server.handleServiceEndpointEvent(localService, oldLocalService)
			},
			DeleteFunc: func(obj interface{}) {
				ep, ok := obj.(*v1.Endpoints)
				if !ok {
					ep = obj.(cache.DeletedFinalStateUnknown).Obj.(*v1.Endpoints)
				}
				oldLocalService := server.resolveLocalServiceFromEndpoints(ep)
				server.handleServiceEndpointEvent(nil, oldLocalService)
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

func IsLocalOnly(service *v1.Service) bool {
	return service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal
}

func IsServiceAffinityClient(service *v1.Service) bool {
	return service.Spec.SessionAffinity == v1.ServiceAffinityClientIP
}

func GetServiceAffinityTimeoutSeconds(service *v1.Service) int32 {
	sac := service.Spec.SessionAffinityConfig
	if sac == nil {
		return 10800 /* default to 3 hours */
	}
	if sac.ClientIP == nil {
		return 10800 /* default to 3 hours */
	}
	if sac.ClientIP.TimeoutSeconds == nil {
		return 10800 /* default to 3 hours */
	}
	return *sac.ClientIP.TimeoutSeconds
}

func ServiceID(service *v1.Service) string {
	return service.Namespace + "/" + service.Name
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

/**
 * Compares two lists of service.Entry, match them and return those
 * who should be deleted (first) and then re-added. It supports update
 * when the entries can be updated with the add call
 */
func (service *LocalService) CompareEntryLists(oldService *LocalService) (added []CnatTranslateEntryVPPState, deleted []CnatTranslateEntryVPPState, changed bool) {
	if service == nil && oldService == nil {
		changed = false
	} else if service == nil {
		deleted = oldService.Entries
		changed = true
	} else if oldService == nil {
		changed = true
		added = service.Entries
	} else {
		oldMap := make(map[string]CnatTranslateEntryVPPState)
		newMap := make(map[string]CnatTranslateEntryVPPState)
		for _, elem := range oldService.Entries {
			oldMap[elem.Key()] = elem
		}
		for _, elem := range service.Entries {
			newMap[elem.Key()] = elem
		}
		for _, elem := range oldService.Entries {
			match, found := newMap[elem.Key()]
			/* delete if not found in current map, or if we can't just update */
			if !found {
				deleted = append(deleted, elem)
			} else if match.Entry.Equal(&elem.Entry) == types.ShouldRecreateObj {
				deleted = append(deleted, elem)
			}
		}
		for _, elem := range service.Entries {
			match, found := oldMap[elem.Key()]
			/* add if previously not found, just skip if objects are really equal */
			if !found {
				added = append(added, elem)
			} else if match.Entry.Equal(&elem.Entry) != types.AreEqualObj {
				added = append(added, elem)
			}
		}
		changed = len(added)+len(deleted) > 0
	}
	return
}

/**
 * Compares two lists of service.SpecificRoutes, match them and return those
 * who should be deleted and then added.
 */
func (service *LocalService) CompareSpecificRoutes(oldService *LocalService) (added []net.IP, deleted []net.IP, changed bool) {
	if service == nil && oldService == nil {
		changed = false
	} else if service == nil {
		changed = true
		deleted = oldService.SpecificRoutes
	} else if oldService == nil {
		changed = true
		added = service.SpecificRoutes
	} else {
		added, deleted, changed = common.CompareIPList(oldService.SpecificRoutes, service.SpecificRoutes)
	}
	return added, deleted, changed
}

func (s *Server) handleServiceEndpointEvent(service *LocalService, oldService *LocalService) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if added, deleted, changed := service.CompareEntryLists(oldService); changed {
		s.deleteServiceEntries(deleted)
		s.addServiceEntries(added)
	}
	if added, deleted, changed := service.CompareSpecificRoutes(oldService); changed {
		s.advertiseSpecificRoute(added, deleted)
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

	err = s.vpp.CnatPurge()
	if err != nil {
		return err
	}

	if config.EnableServices {
		s.t.Go(func() error { s.serviceInformer.Run(t.Dying()); return nil })
		s.t.Go(func() error { s.endpointInformer.Run(t.Dying()); return nil })
	}

	<-s.t.Dying()

	s.log.Infof("Service Server returned")

	return nil
}
