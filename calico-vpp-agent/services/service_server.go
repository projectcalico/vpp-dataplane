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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
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
	log                    *logrus.Entry
	vpp                    *vpplink.VppLink
	endpointslicesStore    cache.Store
	serviceStore           cache.Store
	serviceInformer        cache.Controller
	endpointslicesInformer cache.Controller

	lock sync.Mutex /* protects handleServiceEndpointEvent(s)/Serve */
	/* and protects the endpointSlicesByService map */

	BGPConf     *calicov3.BGPConfigurationSpec
	nodeBGPSpec *common.LocalNodeSpec

	serviceStateMap map[string]ServiceState
	// cache of all endpoint slices, by service name
	endpointSlicesByService map[string]map[string]*discoveryv1.EndpointSlice
	endpointSlices          map[string]*discoveryv1.EndpointSlice

	t tomb.Tomb
}

func (s *Server) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.BGPConf = bgpConf
}

func (s *Server) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func (s *Server) ParseServiceAnnotations(annotations map[string]string, name string) *serviceInfo {
	var err []error
	svc := &serviceInfo{}
	for key, value := range annotations {
		switch key {
		case config.LBTypeAnnotation:
			switch strings.ToLower(value) {
			case "ecmp":
				svc.lbType = lbTypeECMP
			case "maglev":
				svc.lbType = lbTypeMaglev
			case "maglevdsr":
				svc.lbType = lbTypeMaglevDSR
			default:
				svc.lbType = lbTypeECMP // default value
				err = append(err, errors.Errorf("Unknown value %s for key %s", value, key))
			}
		case config.HashConfigAnnotation:
			hashConfigList := strings.Split(strings.TrimSpace(value), ",")
			for _, hc := range hashConfigList {
				switch strings.TrimSpace(strings.ToLower(hc)) {
				case "srcport":
					svc.hashConfig |= types.FlowHashSrcPort
				case "dstport":
					svc.hashConfig |= types.FlowHashDstPort
				case "srcaddr":
					svc.hashConfig |= types.FlowHashSrcIP
				case "dstaddr":
					svc.hashConfig |= types.FlowHashDstIP
				case "iproto":
					svc.hashConfig |= types.FlowHashProto
				case "reverse":
					svc.hashConfig |= types.FlowHashReverse
				case "symmetric":
					svc.hashConfig |= types.FlowHashSymetric
				default:
					err = append(err, errors.Errorf("Unknown value %s for key %s", value, key))
				}
			}
		case config.KeepOriginalPacketAnnotation:
			var err1 error
			svc.keepOriginalPacket, err1 = strconv.ParseBool(value)
			if err1 != nil {
				err = append(err, errors.Wrapf(err1, "Unknown value %s for key %s", value, key))
			}
		default:
			continue
		}
		if len(err) != 0 {
			s.log.Errorf("Error parsing annotations for service %s: %s", name, err)
		}
	}
	return svc
}

func (s *Server) resolveLocalServiceFromService(service *v1.Service) *LocalService {
	if service == nil {
		return nil
	}
	return s.GetLocalService(service, s.endpointSlicesByService[objectID(&service.ObjectMeta)])
}

func NewServiceServer(vpp *vpplink.VppLink, k8sclient *kubernetes.Clientset, log *logrus.Entry) *Server {
	server := Server{
		vpp:                     vpp,
		log:                     log,
		serviceStateMap:         make(map[string]ServiceState),
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
					server.lock.Lock()
					localService := server.resolveLocalServiceFromService(service)
					server.handleServiceEndpointEvent(localService, nil)
					server.lock.Unlock()
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
					server.lock.Lock()
					oldLocalService := server.resolveLocalServiceFromService(oldService)
					localService := server.resolveLocalServiceFromService(service)
					server.handleServiceEndpointEvent(localService, oldLocalService)
					server.lock.Unlock()
				},
				DeleteFunc: func(obj interface{}) {
					switch value := obj.(type) {
					case cache.DeletedFinalStateUnknown:
						service, ok := value.Obj.(*v1.Service)
						if !ok {
							panic(fmt.Sprintf("obj.(cache.DeletedFinalStateUnknown).Obj not a (*v1.Service) %v", obj))
						}
						server.deleteServiceByName(objectID(&service.ObjectMeta))
					case *v1.Service:
						server.deleteServiceByName(objectID(&value.ObjectMeta))
					default:
						log.Errorf("unknown type in service deleteFunction %v", obj)
					}
				},
			},
		},
	)

	// ---- Watch EndpointSlices (IPv4 + IPv6) ----
	endpointslicesStore, endpointslicesInformer := cache.NewInformerWithOptions(
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
					newEps, ok := obj.(*discoveryv1.EndpointSlice)
					if !ok {
						panic("wrong type for obj, not *discoveryv1.EndpointSlice")
					}
					svcKey := serviceName(newEps)
					server.lock.Lock()
					if len(server.endpointSlicesByService[svcKey]) == 0 {
						server.endpointSlicesByService[svcKey] = make(map[string]*discoveryv1.EndpointSlice)
					}
					server.endpointSlicesByService[svcKey][objectID(&newEps.ObjectMeta)] = newEps
					server.endpointSlices[objectID(&newEps.ObjectMeta)] = newEps
					svc := server.getServiceFromStore(svcKey)
					if svc != nil {
						server.handleServiceEndpointEvent(server.GetLocalService(svc, server.endpointSlicesByService[svcKey]), nil)
					}
					server.lock.Unlock()
				},
				UpdateFunc: func(_, new interface{}) {
					newEps, ok := new.(*discoveryv1.EndpointSlice)
					if !ok {
						panic("wrong type for obj, not *discoveryv1.EndpointSlice")
					}
					svcKey := serviceName(newEps)
					server.lock.Lock()
					if len(server.endpointSlicesByService[svcKey]) == 0 {
						server.endpointSlicesByService[svcKey] = make(map[string]*discoveryv1.EndpointSlice)
					}
					svc := server.getServiceFromStore(svcKey)
					if svc != nil {
						oldLocal := server.GetLocalService(
							svc,
							server.endpointSlicesByService[svcKey],
						)
						server.endpointSlicesByService[svcKey][objectID(&newEps.ObjectMeta)] = newEps
						server.endpointSlices[objectID(&newEps.ObjectMeta)] = newEps
						newLocal := server.GetLocalService(
							svc,
							server.endpointSlicesByService[svcKey],
						)
						server.handleServiceEndpointEvent(newLocal, oldLocal)
					} else {
						server.log.Debugf("Trying to update endpointslice, Service %s not found", svcKey)
						server.endpointSlicesByService[svcKey][objectID(&newEps.ObjectMeta)] = newEps
						server.endpointSlices[objectID(&newEps.ObjectMeta)] = newEps
					}
					server.lock.Unlock()
				},
				DeleteFunc: func(obj interface{}) {
					key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
					if err != nil {
						panic("wrong type for obj, could not get DeletionHandlingMetaNamespaceKeyFunc")
					} else {
						oldEps, ok := server.endpointSlices[key]
						if ok {
							svcKey := serviceName(oldEps)
							server.lock.Lock()
							svc := server.getServiceFromStore(svcKey)
							if svc != nil {
								oldLocal := server.GetLocalService(
									svc,
									server.endpointSlicesByService[svcKey],
								)
								delete(server.endpointSlicesByService[svcKey], objectID(&oldEps.ObjectMeta))
								if len(server.endpointSlicesByService[svcKey]) == 0 {
									delete(server.endpointSlicesByService, svcKey)
								}
								newLocal := server.GetLocalService(
									svc,
									server.endpointSlicesByService[svcKey],
								)
								server.handleServiceEndpointEvent(oldLocal, newLocal)
							} else {
								server.log.Debugf("Service %s already gone", svcKey)
								delete(server.endpointSlicesByService[svcKey], objectID(&oldEps.ObjectMeta))
								if len(server.endpointSlicesByService[svcKey]) == 0 {
									delete(server.endpointSlicesByService, svcKey)
								}
							}
							delete(server.endpointSlices, key)
							server.lock.Unlock()
						} else {
							server.log.Debugf("endpointslice %s not found in map", key)
						}
					}
				},
			}},
	)

	server.endpointslicesStore = endpointslicesStore
	server.serviceStore = serviceStore
	server.serviceInformer = serviceInformer
	server.endpointslicesInformer = endpointslicesInformer

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

func objectID(meta *metav1.ObjectMeta) string {
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
	for _, serviceCIDR := range *config.ServiceCIDRs {
		err = s.vpp.CnatAddSnatPrefix(serviceCIDR)
		if err != nil {
			s.log.Errorf("Failed to Add Service CIDR %s %v", serviceCIDR, err)
		}
	}
	return nil
}

func serviceName(es *discoveryv1.EndpointSlice) string {
	svc := es.Labels["kubernetes.io/service-name"]
	name := fmt.Sprintf("%s/%s", es.Namespace, svc)
	return name
}

func (s *Server) getServiceFromStore(key string) *v1.Service {
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
			New:  cni.NetworkPod{ContainerIP: serviceIPNet, NetworkVni: 0},
		})
	}

	err = s.vpp.CnatPurge()
	if err != nil {
		return err
	}

	if *config.GetCalicoVppDebug().ServicesEnabled {
		s.t.Go(func() error { s.serviceInformer.Run(t.Dying()); return nil })
		s.t.Go(func() error { s.endpointslicesInformer.Run(t.Dying()); return nil })
	}

	<-s.t.Dying()

	s.log.Warn("Service Server returned")

	return nil
}
