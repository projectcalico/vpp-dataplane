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

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"

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

func buildCnatEntryForServicePort(servicePort *v1.ServicePort, service *v1.Service, ep *v1.Endpoints, serviceIP net.IP, isNodePort bool) *CnatTranslateEntryVPPState {
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

	return &CnatTranslateEntryVPPState{
		Entry: types.CnatTranslateEntry{
			Proto: getServicePortProto(servicePort.Protocol),
			Endpoint: types.CnatEndpoint{
				Port: getCnatVipDstPort(servicePort, isNodePort),
				IP:   serviceIP,
			},
			Backends: backends,
			IsRealIP: isNodePort,
			LbType:   getCnatLBType(),
			ID:       vpplink.InvalidID,
		},
		OwnerServiceID: ServiceID(service),
	}
}

func (s *Server) GetCnatEntries(service *v1.Service, ep *v1.Endpoints) (entries []CnatTranslateEntryVPPState, specificRoutes []net.IP) {
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	nodeIP := s.getNodeIP(vpplink.IsIP6(clusterIP))
	for _, servicePort := range service.Spec.Ports {
		if !clusterIP.IsUnspecified() {
			entry := buildCnatEntryForServicePort(&servicePort, service, ep, clusterIP, false /* isNodePort */)
			entries = append(entries, *entry)
		}

		for _, eip := range service.Spec.ExternalIPs {
			extIP := net.ParseIP(eip)
			if !extIP.IsUnspecified() {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, extIP, false /* isNodePort */)
				entries = append(entries, *entry)
				if IsLocalOnly(service) && len(entry.Entry.Backends) > 0 {
					specificRoutes = append(specificRoutes, extIP)
				}
			}
		}

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(ingress.IP)
			if !ingressIP.IsUnspecified() {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, ingressIP, false /* isNodePort */)
				entries = append(entries, *entry)
				if IsLocalOnly(service) && len(entry.Entry.Backends) > 0 {
					specificRoutes = append(specificRoutes, ingressIP)
				}
			}
		}

		if service.Spec.Type == v1.ServiceTypeNodePort {
			if !nodeIP.IsUnspecified() {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, nodeIP, true /* isNodePort */)
				entries = append(entries, *entry)
			}
		}
	}
	return entries, specificRoutes
}

func (s *Server) deleteCnatEntry(entry *CnatTranslateEntryVPPState) (err error) {
	s.log.Infof("svc(del) key=%s %s vpp-id=%d", entry.Key(), entry.String(), entry.Entry.ID)
	previousEntry, previousFound := s.stateMap[entry.Key()]
	if !previousFound {
		s.log.Infof("Cnat entry not found")
		return nil
	}
	if previousEntry.OwnerServiceID != entry.OwnerServiceID {
		s.log.Infof("Cnat entry found but changed owner since")
		return nil
	}

	err = s.vpp.CnatTranslateDel(previousEntry.Entry.ID)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) updateCnatEntry(entry *CnatTranslateEntryVPPState) (err error) {
	previousEntry, previousFound := s.stateMap[entry.Key()]
	if previousFound && entry.Entry.Equal(&previousEntry.Entry) {
		s.log.Infof("svc(same) %s", entry.String())
		/* OwnerServiceID might have changed */
		previousEntry.OwnerServiceID = entry.OwnerServiceID
		s.stateMap[entry.Key()] = previousEntry
	} else {
		entryID, err := s.vpp.CnatTranslateAdd(&entry.Entry)
		if err != nil {
			return errors.Wrapf(err, "NAT:Error adding translation %s", entry.String())
		}
		entry.Entry.ID = entryID
		s.log.Infof("svc(add) key=%s %s vpp-id=%d", entry.Key(), entry.String(), entryID)
		s.stateMap[entry.Key()] = *entry
	}
	return nil
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

func (s *Server) advertiseSpecificRoute(IPAddress net.IP, withdraw bool) {
	if s.isAddressExternalServiceIP(IPAddress) {
		if withdraw {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.LocalPodAddressDeleted,
				Old:  common.ToMaxLenCIDR(IPAddress),
			})
			s.log.Infof("Withdrawing advertisement for service specific route Addresses %+v", IPAddress)
		} else {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.LocalPodAddressAdded,
				New:  common.ToMaxLenCIDR(IPAddress),
			})
			s.log.Infof("Announcing service specific route Addresses %+v", IPAddress)
		}
	}
}

func (s *Server) addServicePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	s.log.Debugf("Service update: svc:%s entry:%+v", ServiceID(service), ep.Subsets)

	entries, specificRoutes := s.GetCnatEntries(service, ep)
	for _, specificRoute := range specificRoutes {
		s.advertiseSpecificRoute(specificRoute, false /* isWithdraw */)
	}
	for _, entry := range entries {
		err := s.updateCnatEntry(&entry)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) delServicePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	s.log.Debugf("Service del: svc:%s entry:%+v", ServiceID(service), ep.Subsets)

	entries, specificRoutes := s.GetCnatEntries(service, ep)
	for _, specificRoute := range specificRoutes {
		s.advertiseSpecificRoute(specificRoute, true /* isWithdraw */)
	}
	for _, entry := range entries {
		err := s.deleteCnatEntry(&entry)
		if err != nil {
			return err
		}
	}

	return nil
}
