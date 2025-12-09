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

	v1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/util/intstr"

	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func getCnatBackendDstPort(servicePort *v1.ServicePort, endpointPort *discoveryv1.EndpointPort) int32 {
	targetPort := servicePort.TargetPort
	if targetPort.Type == intstr.Int {
		if targetPort.IntVal == 0 {
			// Unset targetport
			return servicePort.Port
		} else {
			return targetPort.IntVal
		}
	} else {
		if endpointPort.Port != nil {
			return *endpointPort.Port
		} else {
			// shouldn't happen
			return 0
		}
	}
}

func getServicePortProto(proto v1.Protocol) types.IPProto {
	switch proto {
	case v1.ProtocolUDP:
		return types.UDP
	case v1.ProtocolSCTP:
		return types.SCTP
	case v1.ProtocolTCP:
		return types.TCP
	default:
		return types.TCP
	}
}

func isEndpointAddressLocal(endpointAddress *discoveryv1.Endpoint) bool {
	if endpointAddress != nil && endpointAddress.NodeName != nil && *endpointAddress.NodeName != *config.NodeName {
		return false
	}
	return true
}

func getCnatLBType(lbType lbType) types.CnatLbType {
	if lbType == lbTypeMaglev || lbType == lbTypeMaglevDSR {
		return types.MaglevLB
	}
	return types.DefaultLB
}

func getCnatVipDstPort(servicePort *v1.ServicePort, isNodePort bool) uint16 {
	if isNodePort {
		return uint16(servicePort.NodePort)
	}
	return uint16(servicePort.Port)
}

func (s *Server) buildCnatEntryForServicePort(servicePort *v1.ServicePort, epslices []*discoveryv1.EndpointSlice, serviceIP net.IP, isNodePort bool, svcInfo serviceInfo, isLocalOnly bool) *types.CnatTranslateEntry {
	backends := make([]types.CnatEndpointTuple, 0)
	// Find the endpoint subset port that exposes the port we're interested in
	for _, epslice := range epslices {
		for _, ep := range epslice.Endpoints {
			for _, endpointPort := range epslice.Ports {
				if servicePort.Name == *endpointPort.Name {
					if endpointPort.Port == nil {
						// null ports not supported
						s.log.Warnf("null ports not supported for port %s", *endpointPort.Name)
						continue
					}
					for _, endpointAddress := range ep.Addresses {
						var flags uint8 = 0
						if !isEndpointAddressLocal(&ep) && isLocalOnly {
							continue
						}
						if !isEndpointAddressLocal(&ep) {
							/* dont NAT to remote endpoints if maglevDSR unless this is a nodeport */
							if svcInfo.lbType == lbTypeMaglevDSR && !isNodePort {
								flags = flags | types.CnatNoNat
							}
						}
						ip := net.ParseIP(endpointAddress)
						if ip != nil {
							backend := types.CnatEndpointTuple{
								DstEndpoint: types.CnatEndpoint{
									Port: uint16(getCnatBackendDstPort(servicePort, &endpointPort)),
									IP:   ip,
								},
								Flags: flags,
							}
							/* In nodeports, we need to sNAT when endpoint is not local to have a symmetric traffic */
							if isNodePort && !isEndpointAddressLocal(&ep) {
								backend.SrcEndpoint.IP = serviceIP
							}
							/* Only append backend if it has the same address family as the service IP */
							/* we don't nat v4 to v6 and vice versa */
							if (ip.To4() != nil) == (serviceIP.To4() != nil) {
								backends = append(backends, backend)
							}
						}
					}
					break
				}
			}
		}
	}

	return &types.CnatTranslateEntry{
		Proto: getServicePortProto(servicePort.Protocol),
		Endpoint: types.CnatEndpoint{
			Port: getCnatVipDstPort(servicePort, isNodePort),
			IP:   serviceIP,
		},
		Backends:   backends,
		IsRealIP:   isNodePort,
		LbType:     getCnatLBType(svcInfo.lbType),
		HashConfig: svcInfo.hashConfig,
	}
}

func (s *Server) GetLocalService(service *v1.Service, epSlicesMap map[string]*discoveryv1.EndpointSlice) (localService *LocalService) {
	epSlices := []*discoveryv1.EndpointSlice{}
	for _, epslice := range epSlicesMap {
		epSlices = append(epSlices, epslice)
	}
	localService = &LocalService{
		Entries:        make([]types.CnatTranslateEntry, 0),
		SpecificRoutes: make([]net.IP, 0),
		ServiceID:      objectID(&service.ObjectMeta), /* ip.ObjectMeta should yield the same id */
	}

	serviceSpec := s.ParseServiceAnnotations(service.Annotations, service.Name)
	var clusterIPs []net.IP
	var nodeIPs []net.IP
	for _, cip := range service.Spec.ClusterIPs {
		clusterIPs = append(clusterIPs, net.ParseIP(cip))
		nodeIPs = append(nodeIPs, s.getNodeIP(vpplink.IsIP6(net.ParseIP(cip))))
	}
	for _, servicePort := range service.Spec.Ports {
		for _, cip := range clusterIPs {
			if !cip.IsUnspecified() && len(cip) > 0 {
				entry := s.buildCnatEntryForServicePort(&servicePort, epSlices, cip, false /* isNodePort */, *serviceSpec, InternalIsLocalOnly(service))
				localService.Entries = append(localService.Entries, *entry)
			}
		}

		for _, eip := range service.Spec.ExternalIPs {
			extIP := net.ParseIP(eip)
			if !extIP.IsUnspecified() && len(extIP) > 0 {
				entry := s.buildCnatEntryForServicePort(&servicePort, epSlices, extIP, false /* isNodePort */, *serviceSpec, ExternalIsLocalOnly(service))
				localService.Entries = append(localService.Entries, *entry)
				if ExternalIsLocalOnly(service) && len(entry.Backends) > 0 {
					localService.SpecificRoutes = append(localService.SpecificRoutes, extIP)
				}
			}
		}

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(ingress.IP)
			if !ingressIP.IsUnspecified() && len(ingressIP) > 0 {
				entry := s.buildCnatEntryForServicePort(&servicePort, epSlices, ingressIP, false /* isNodePort */, *serviceSpec, ExternalIsLocalOnly(service))
				localService.Entries = append(localService.Entries, *entry)
				if ExternalIsLocalOnly(service) && len(entry.Backends) > 0 {
					localService.SpecificRoutes = append(localService.SpecificRoutes, ingressIP)
				}
			}
		}

		if service.Spec.Type == v1.ServiceTypeNodePort {
			for _, nip := range nodeIPs {
				if !nip.IsUnspecified() && len(nip) > 0 {
					entry := s.buildCnatEntryForServicePort(&servicePort, epSlices, nip, true /* isNodePort */, *serviceSpec, false)
					localService.Entries = append(localService.Entries, *entry)
				}
			}
		}

		// Create NodePort for external LB
		// Note: type=LoadBalancer only makes sense on cloud providers which support external load balancers and the actual
		// creation of the load balancer happens asynchronously.
		if service.Spec.Type == v1.ServiceTypeLoadBalancer && *service.Spec.AllocateLoadBalancerNodePorts {
			for _, nip := range nodeIPs {
				if !nip.IsUnspecified() && len(nip) > 0 {
					entry := s.buildCnatEntryForServicePort(&servicePort, epSlices, nip, true /* isNodePort */, *serviceSpec, false)
					localService.Entries = append(localService.Entries, *entry)
				}
			}
		}
	}
	return
}

func (s *Server) isAddressExternalServiceIP(IPAddress net.IP) bool {
	_, serviceExternalIPNets, serviceLBIPNets := s.getServiceIPs()
	for _, serviceIPNet := range append(serviceExternalIPNets, serviceLBIPNets...) {
		if serviceIPNet.Contains(IPAddress) {
			return true
		}
	}
	return false
}

func (s *Server) advertiseSpecificRoute(added []net.IP, deleted []net.IP) {
	for _, specificRoute := range deleted {
		if s.isAddressExternalServiceIP(specificRoute) {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.LocalPodAddressDeleted,
				Old:  cni.NetworkPod{ContainerIP: common.ToMaxLenCIDR(specificRoute), NetworkVni: 0},
			})
			s.log.Infof("Withdrawing advertisement for service specific route Addresses %+v", specificRoute)
		}
	}
	for _, specificRoute := range added {
		if s.isAddressExternalServiceIP(specificRoute) {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.LocalPodAddressAdded,
				New:  cni.NetworkPod{ContainerIP: common.ToMaxLenCIDR(specificRoute), NetworkVni: 0},
			})
			s.log.Infof("Announcing service specific route Addresses %+v", specificRoute)
		}
	}
}

func (s *Server) deleteServiceEntry(key, serviceID string) {
	if _, found := s.serviceIDByKey[key]; !found {
		s.log.Warnf("svc(del) entry %s not found", key)
		return
	} else if s.serviceIDByKey[key] != serviceID {
		// do nothing in vpp, this service is not activated
		s.log.Debugf("svc(del) entry %s not created in vpp for service %s", key, serviceID)
	} else if len(s.cnatEntryByKeyAndSid[key]) == 1 {
		err := s.vpp.CnatTranslateDel(s.cnatEntryByKeyAndSid[key][serviceID].vppID)
		if err != nil {
			s.log.Errorf("Cnat entry delete errored %s", err)
		}
		delete(s.serviceIDByKey, key)
	} else if len(s.cnatEntryByKeyAndSid[key]) > 1 {
		// the entry is referenced by another service, recreate the lexicographically smallest service entry
		s.log.Warnf("svc(del) entry %s was referenced by multiple services", key)
		var chosenService string
		for svc := range s.cnatEntryByKeyAndSid[key] {
			if (chosenService == "" || svc < chosenService) && chosenService != serviceID {
				chosenService = svc
			}
		}
		s.log.Infof("svc(re-add) adding service %s for entry %s", chosenService, key)
		entryID, err := s.vpp.CnatTranslateAdd(&s.cnatEntryByKeyAndSid[key][chosenService].entry)
		if err != nil {
			s.log.Errorf("svc(add) Error adding translation %s %s", s.cnatEntryByKeyAndSid[key][chosenService].entry.String(), err)
		}
		s.cnatEntryByKeyAndSid[key][chosenService].vppID = entryID
		s.serviceIDByKey[key] = chosenService
	} else {
		panic("this should not happen")
	}
	delete(s.cnatEntryByKeyAndSid[key], serviceID)
	delete(s.cnatEntryBySidAndKey[serviceID], key)
	// cleanup maps if empty
	if len(s.cnatEntryByKeyAndSid[key]) == 0 {
		delete(s.cnatEntryByKeyAndSid, key)
	}
	if len(s.cnatEntryBySidAndKey[serviceID]) == 0 {
		delete(s.cnatEntryBySidAndKey, serviceID)
	}
}

func (s *Server) deleteServiceEntries(entries []types.CnatTranslateEntry, oldService *LocalService) {
	for _, entry := range entries {
		s.deleteServiceEntry(entry.Key(), oldService.ServiceID)
	}
}

func (s *Server) deleteServiceByName(serviceID string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for key := range s.cnatEntryBySidAndKey[serviceID] {
		s.deleteServiceEntry(key, serviceID)
	}
}

func (s *Server) addServiceEntries(entries []types.CnatTranslateEntry, service *LocalService) {
	for _, entry := range entries {
		entryID, err := s.vpp.CnatTranslateAdd(&entry)
		if err != nil {
			s.log.Errorf("svc(add) Error adding translation %s %s", entry.String(), err)
			continue
		}
		if _, found := s.cnatEntryBySidAndKey[service.ServiceID]; !found {
			s.log.Infof("svc(add) adding service id %s to cache", service.ServiceID)
			s.cnatEntryBySidAndKey[service.ServiceID] = make(map[string]*cnatEntry)
		}
		if _, found := s.cnatEntryByKeyAndSid[entry.Key()]; !found {
			s.log.Infof("svc(add) adding entry key=%s to cache", entry.Key())
			s.cnatEntryByKeyAndSid[entry.Key()] = make(map[string]*cnatEntry)
		}
		s.log.Infof("svc(add) adding service %s to entry key=%s cache", service.ServiceID, entry.Key())
		s.cnatEntryByKeyAndSid[entry.Key()][service.ServiceID] = &cnatEntry{
			entry: entry,
			vppID: entryID,
		}
		s.cnatEntryBySidAndKey[service.ServiceID][entry.Key()] = &cnatEntry{
			entry: entry,
			vppID: entryID,
		}
		s.serviceIDByKey[entry.Key()] = service.ServiceID
		if len(s.cnatEntryByKeyAndSid[entry.Key()]) > 1 {
			s.log.Warnf("svc(add) entry %s is referenced by multiple services; overriding previous value and using the latest", entry.Key())
			for svc := range s.cnatEntryByKeyAndSid[entry.Key()] {
				if svc != service.ServiceID {
					s.cnatEntryByKeyAndSid[entry.Key()][svc].vppID = ^uint32(0)
				}
			}
		}
	}
}
