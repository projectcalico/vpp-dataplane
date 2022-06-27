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

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func getCnatBackendDstPort(servicePort *v1.ServicePort, endpointPort *v1.EndpointPort) uint16 {
	targetPort := servicePort.TargetPort
	if targetPort.Type == intstr.Int {
		if targetPort.IntVal == 0 {
			// Unset targetport
			return uint16(servicePort.Port)
		} else {
			return uint16(targetPort.IntVal)
		}
	} else {
		return uint16(endpointPort.Port)
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

func isEndpointAddressLocal(endpointAddress *v1.EndpointAddress) bool {
	if endpointAddress != nil && endpointAddress.NodeName != nil && *endpointAddress.NodeName != config.NodeName {
		return false
	}
	return true
}

func getCnatLBType() types.CnatLbType {
	if config.EnableMaglev {
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

func buildCnatEntryForServicePort(servicePort *v1.ServicePort, service *v1.Service, ep *v1.Endpoints, serviceIP net.IP, isNodePort bool) *types.CnatTranslateEntry {
	backends := make([]types.CnatEndpointTuple, 0)
	isLocalOnly := IsLocalOnly(service)
	if isNodePort {
		isLocalOnly = false
	}
	// Find the endpoint subset port that exposes the port we're interested in
	for _, endpointSubset := range ep.Subsets {
		for _, endpointPort := range endpointSubset.Ports {
			if servicePort.Name == endpointPort.Name {
				for _, endpointAddress := range endpointSubset.Addresses {
					var flags uint8 = 0
					if !isEndpointAddressLocal(&endpointAddress) && isLocalOnly {
						continue
					}
					if !isEndpointAddressLocal(&endpointAddress) {
						/* dont NAT to remote endpoints unless this is a nodeport */
						if config.EnableMaglev && !isNodePort {
							flags = flags | types.CnatNoNat
						}
					}
					ip := net.ParseIP(endpointAddress.IP)
					if ip != nil {
						backend := types.CnatEndpointTuple{
							DstEndpoint: types.CnatEndpoint{
								Port: getCnatBackendDstPort(servicePort, &endpointPort),
								IP:   ip,
							},
							Flags: flags,
						}
						/* In nodeports, we also sNAT */
						if isNodePort {
							backend.SrcEndpoint.IP = serviceIP
						}
						backends = append(backends, backend)
					}
				}
				break
			}
		}
	}

	return &types.CnatTranslateEntry{
		Proto: getServicePortProto(servicePort.Protocol),
		Endpoint: types.CnatEndpoint{
			Port: getCnatVipDstPort(servicePort, isNodePort),
			IP:   serviceIP,
		},
		Backends: backends,
		IsRealIP: isNodePort,
		LbType:   getCnatLBType(),
	}
}

func (s *Server) GetLocalService(service *v1.Service, ep *v1.Endpoints) (localService *LocalService) {
	localService = &LocalService{
		Entries:        make([]types.CnatTranslateEntry, 0),
		SpecificRoutes: make([]net.IP, 0),
		ServiceID:      serviceID(&service.ObjectMeta), /* ip.ObjectMeta should yield the same id */
	}

	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	nodeIP := s.getNodeIP(vpplink.IsIP6(clusterIP))
	for _, servicePort := range service.Spec.Ports {
		if !clusterIP.IsUnspecified() {
			entry := buildCnatEntryForServicePort(&servicePort, service, ep, clusterIP, false /* isNodePort */)
			localService.Entries = append(localService.Entries, *entry)
		}

		for _, eip := range service.Spec.ExternalIPs {
			extIP := net.ParseIP(eip)
			if !extIP.IsUnspecified() {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, extIP, false /* isNodePort */)
				localService.Entries = append(localService.Entries, *entry)
				if IsLocalOnly(service) && len(entry.Backends) > 0 {
					localService.SpecificRoutes = append(localService.SpecificRoutes, extIP)
				}
			}
		}

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(ingress.IP)
			if !ingressIP.IsUnspecified() {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, ingressIP, false /* isNodePort */)
				localService.Entries = append(localService.Entries, *entry)
				if IsLocalOnly(service) && len(entry.Backends) > 0 {
					localService.SpecificRoutes = append(localService.SpecificRoutes, ingressIP)
				}
			}
		}

		if service.Spec.Type == v1.ServiceTypeNodePort {
			if !nodeIP.IsUnspecified() {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, nodeIP, true /* isNodePort */)
				localService.Entries = append(localService.Entries, *entry)
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
				New: cni.NetworkPod{ContainerIP: common.ToMaxLenCIDR(specificRoute), NetworkVni: 0},
			})
			s.log.Infof("Announcing service specific route Addresses %+v", specificRoute)
		}
	}
}

func (s *Server) deleteServiceEntries(entries []types.CnatTranslateEntry, oldService *LocalService) {
	for _, entry := range entries {
		oldServiceState, found := s.serviceStateMap[entry.Key()]
		if !found {
			s.log.Infof("svc(del) key=%s Cnat entry not found", entry.Key())
			continue
		}
		s.log.Infof("svc(del) key=%s %s vpp-id=%d", entry.Key(), entry.String(), oldServiceState.VppID)
		if oldServiceState.OwnerServiceID != oldService.ServiceID {
			s.log.Infof("Cnat entry found but changed owner since")
			continue
		}

		err := s.vpp.CnatTranslateDel(oldServiceState.VppID)
		if err != nil {
			s.log.Errorf("Cnat entry delete errored %s", err)
			continue
		}
		delete(s.serviceStateMap, entry.Key())
	}
}

func (s *Server) deleteServiceByName(serviceID string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for key, oldServiceState := range s.serviceStateMap {
		if oldServiceState.OwnerServiceID != serviceID {
			continue
		}
		err := s.vpp.CnatTranslateDel(oldServiceState.VppID)
		if err != nil {
			s.log.Errorf("Cnat entry delete errored %s", err)
			continue
		}
		delete(s.serviceStateMap, key)
	}

}

func (s *Server) sameServiceEntries(entries []types.CnatTranslateEntry, service *LocalService) {
	for _, entry := range entries {
		if serviceState, found := s.serviceStateMap[entry.Key()]; found {
			serviceState.OwnerServiceID = service.ServiceID
			s.serviceStateMap[entry.Key()] = serviceState
		} else {
			s.log.Warnf("Cnat entry not found key=%s", entry.Key())
		}
	}
}

func (s *Server) addServiceEntries(entries []types.CnatTranslateEntry, service *LocalService) {
	for _, entry := range entries {
		entryID, err := s.vpp.CnatTranslateAdd(&entry)
		if err != nil {
			s.log.Errorf("svc(add) Error adding translation %s %s", entry.String(), err)
			continue
		}
		s.log.Infof("svc(add) key=%s %s vpp-id=%d", entry.Key(), entry.String(), entryID)
		s.serviceStateMap[entry.Key()] = ServiceState{
			OwnerServiceID: service.ServiceID,
			VppID:          entryID,
		}
	}
}
