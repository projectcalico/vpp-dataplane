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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

/**
 * Service descriptions from the API are resolved into
 * slices of LocalService, this allows to diffs between
 * previous & expected state in VPP
 */
type LocalService struct {
	Entries        []types.CnatTranslateEntry
	SpecificRoutes []net.IP
	ServiceID      string
}

/**
 * Store VPP's state in a map [CnatTranslateEntry.Key()]->ServiceState
 */
type ServiceState struct {
	OwnerServiceID string /* serviceID(service.ObjectMeta) of the service that created this entry */
	VppID          uint32 /* cnat translation ID in VPP */
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

	serviceStateMap map[string]ServiceState

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
		s.log.Debugf("svc() no endpoints found for service=%s", serviceID(&service.ObjectMeta))
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
		s.log.Debugf("svc() no svc found for endpoints=%s", serviceID(&ep.ObjectMeta))
		return nil
	}
	return s.GetLocalService(service, ep)
}

func NewServiceServer(vpp *vpplink.VppLink, k8sclient *kubernetes.Clientset, log *logrus.Entry) *Server {
	server := Server{
		vpp:             vpp,
		log:             log,
		serviceStateMap: make(map[string]ServiceState),
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
				server.deleteServiceByName(serviceID(&service.ObjectMeta))
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
				server.deleteServiceByName(serviceID(&ep.ObjectMeta))
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

func serviceID(meta *metav1.ObjectMeta) string {
	return meta.Namespace + "/" + meta.Name
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
func compareEntryLists(service *LocalService, oldService *LocalService) (added, same, deleted []types.CnatTranslateEntry, changed bool) {
	if service == nil && oldService == nil {
	} else if service == nil {
		deleted = oldService.Entries
	} else if oldService == nil {
		added = service.Entries
	} else {
		oldMap := make(map[string]types.CnatTranslateEntry)
		newMap := make(map[string]types.CnatTranslateEntry)
		for _, elem := range oldService.Entries {
			oldMap[elem.Key()] = elem
		}
		for _, elem := range service.Entries {
			newMap[elem.Key()] = elem
		}
		for _, oldService := range oldService.Entries {
			newService, found := newMap[oldService.Key()]
			/* delete if not found in current map, or if we can't just update */
			if !found {
				deleted = append(deleted, oldService)
			} else if newService.Equal(&oldService) == types.ShouldRecreateObj {
				deleted = append(deleted, oldService)
			} else {
				same = append(same, oldService)
			}
		}
		for _, newService := range service.Entries {
			oldService, found := oldMap[newService.Key()]
			/* add if previously not found, just skip if objects are really equal */
			if !found {
				added = append(added, newService)
			} else if newService.Equal(&oldService) != types.AreEqualObj {
				added = append(added, newService)
			}
		}
	}
	changed = len(added)+len(deleted) > 0
	return
}

/**
 * Compares two lists of service.SpecificRoutes, match them and return those
 * who should be deleted and then added.
 */
func compareSpecificRoutes(service *LocalService, oldService *LocalService) (added []net.IP, deleted []net.IP, changed bool) {
	if service == nil && oldService == nil {
		changed = false
	} else if service == nil {
		changed = true
		deleted = oldService.SpecificRoutes
	} else if oldService == nil {
		changed = true
		added = service.SpecificRoutes
	} else {
		added, deleted, changed = common.CompareIPList(service.SpecificRoutes, oldService.SpecificRoutes)
	}
	return added, deleted, changed
}

func (s *Server) handleServiceEndpointEvent(service *LocalService, oldService *LocalService) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if added, same, deleted, changed := compareEntryLists(service, oldService); changed {
		s.deleteServiceEntries(deleted, oldService)
		s.sameServiceEntries(same, service)
		s.addServiceEntries(added, service)
	}
	if added, deleted, changed := compareSpecificRoutes(service, oldService); changed {
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
			New: cni.NetworkPod{ContainerIP: serviceIPNet, NetworkVni: 0},
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
