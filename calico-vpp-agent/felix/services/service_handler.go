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
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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

type ServiceHandler struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	serviceStateMap map[string]ServiceState
}

func NewServiceHandler(vpp *vpplink.VppLink, cache *cache.Cache, log *logrus.Entry) *ServiceHandler {
	return &ServiceHandler{
		vpp:             vpp,
		log:             log,
		cache:           cache,
		serviceStateMap: make(map[string]ServiceState),
	}
}

func (s *ServiceHandler) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	s.cache.BGPConf = bgpConf
}

func (s *ServiceHandler) configureSnat() (err error) {
	err = s.vpp.CnatSetSnatAddresses(s.getNodeIP(false /* isv6 */), s.getNodeIP(true /* isv6 */))
	if err != nil {
		s.log.Errorf("Failed to configure SNAT addresses %v", err)
	}
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.cache.NodeBGPSpec)
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

func (s *ServiceHandler) getServiceIPs() ([]*net.IPNet, []*net.IPNet, []*net.IPNet) {
	var serviceClusterIPNets []*net.IPNet
	var serviceExternalIPNets []*net.IPNet
	var serviceLBIPNets []*net.IPNet
	for _, serviceClusterIP := range s.cache.BGPConf.ServiceClusterIPs {
		_, netIP, err := net.ParseCIDR(serviceClusterIP.CIDR)
		if err != nil {
			s.log.Error(err)
			continue
		}
		serviceClusterIPNets = append(serviceClusterIPNets, netIP)
	}
	for _, serviceExternalIP := range s.cache.BGPConf.ServiceExternalIPs {
		_, netIP, err := net.ParseCIDR(serviceExternalIP.CIDR)
		if err != nil {
			s.log.Error(err)
			continue
		}
		serviceExternalIPNets = append(serviceExternalIPNets, netIP)
	}
	for _, serviceLBIP := range s.cache.BGPConf.ServiceLoadBalancerIPs {
		_, netIP, err := net.ParseCIDR(serviceLBIP.CIDR)
		if err != nil {
			s.log.Error(err)
			continue
		}
		serviceLBIPNets = append(serviceLBIPNets, netIP)
	}

	return serviceClusterIPNets, serviceExternalIPNets, serviceLBIPNets
}

func (s *ServiceHandler) ServiceHandlerInit() error {
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
	return nil
}

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

func buildCnatEntryForServicePort(servicePort *v1.ServicePort, service *v1.Service, ep *v1.Endpoints, serviceIP net.IP, isNodePort bool, svcInfo serviceInfo) *types.CnatTranslateEntry {
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
						if svcInfo.lbType == lbTypeMaglevDSR && !isNodePort {
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
						/* In nodeports, we need to sNAT when endpoint is not local to have a symmetric traffic */
						if isNodePort && !isEndpointAddressLocal(&endpointAddress) {
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
		Backends:   backends,
		IsRealIP:   isNodePort,
		LbType:     getCnatLBType(svcInfo.lbType),
		HashConfig: svcInfo.hashConfig,
	}
}

func (s *ServiceHandler) OnServiceEndpointsUpdate(evt *common.ServiceEndpointsUpdate) {
	service := s.getLocalService(evt.New)
	oldService := s.getLocalService(evt.Old)
	if added, same, deleted, changed := compareEntryLists(service, oldService); changed {
		s.deleteServiceEntries(deleted, oldService)
		s.sameServiceEntries(same, service)
		s.addServiceEntries(added, service)
	}
	if added, deleted, changed := compareSpecificRoutes(service, oldService); changed {
		s.advertiseSpecificRoute(added, deleted)
	}
}

func (s *ServiceHandler) getNodeIP(isv6 bool) net.IP {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(s.cache.NodeBGPSpec)
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

func ServiceID(meta *metav1.ObjectMeta) string {
	return meta.Namespace + "/" + meta.Name
}

func (s *ServiceHandler) getLocalService(serviceAndEndpoints *common.ServiceAndEndpoints) (localService *LocalService) {
	if serviceAndEndpoints == nil {
		return nil
	}
	service := serviceAndEndpoints.Service
	ep := serviceAndEndpoints.Endpoints

	localService = &LocalService{
		Entries:        make([]types.CnatTranslateEntry, 0),
		SpecificRoutes: make([]net.IP, 0),
		ServiceID:      ServiceID(&service.ObjectMeta), /* ip.ObjectMeta should yield the same id */
	}

	serviceSpec := s.ParseServiceAnnotations(service.Annotations, service.Name)
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	nodeIP := s.getNodeIP(vpplink.IsIP6(clusterIP))
	for _, servicePort := range service.Spec.Ports {
		if !clusterIP.IsUnspecified() && len(clusterIP) > 0 {
			entry := buildCnatEntryForServicePort(&servicePort, service, ep, clusterIP, false /* isNodePort */, *serviceSpec)
			localService.Entries = append(localService.Entries, *entry)
		}

		for _, eip := range service.Spec.ExternalIPs {
			extIP := net.ParseIP(eip)
			if !extIP.IsUnspecified() && len(extIP) > 0 {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, extIP, false /* isNodePort */, *serviceSpec)
				localService.Entries = append(localService.Entries, *entry)
				if IsLocalOnly(service) && len(entry.Backends) > 0 {
					localService.SpecificRoutes = append(localService.SpecificRoutes, extIP)
				}
			}
		}

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(ingress.IP)
			if !ingressIP.IsUnspecified() && len(ingressIP) > 0 {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, ingressIP, false /* isNodePort */, *serviceSpec)
				localService.Entries = append(localService.Entries, *entry)
				if IsLocalOnly(service) && len(entry.Backends) > 0 {
					localService.SpecificRoutes = append(localService.SpecificRoutes, ingressIP)
				}
			}
		}

		if service.Spec.Type == v1.ServiceTypeNodePort {
			if !nodeIP.IsUnspecified() && len(nodeIP) > 0 {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, nodeIP, true /* isNodePort */, *serviceSpec)
				localService.Entries = append(localService.Entries, *entry)
			}
		}

		// Create NodePort for external LB
		// Note: type=LoadBalancer only makes sense on cloud providers which support external load balancers and the actual
		// creation of the load balancer happens asynchronously.
		if service.Spec.Type == v1.ServiceTypeLoadBalancer && *service.Spec.AllocateLoadBalancerNodePorts {
			if !nodeIP.IsUnspecified() && len(nodeIP) > 0 {
				entry := buildCnatEntryForServicePort(&servicePort, service, ep, nodeIP, true /* isNodePort */, *serviceSpec)
				localService.Entries = append(localService.Entries, *entry)
			}
		}
	}
	return
}

func (s *ServiceHandler) ParseServiceAnnotations(annotations map[string]string, name string) *serviceInfo {
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

func (s *ServiceHandler) isAddressExternalServiceIP(IPAddress net.IP) bool {
	_, serviceExternalIPNets, serviceLBIPNets := s.getServiceIPs()
	for _, serviceIPNet := range append(serviceExternalIPNets, serviceLBIPNets...) {
		if serviceIPNet.Contains(IPAddress) {
			return true
		}
	}
	return false
}

func (s *ServiceHandler) advertiseSpecificRoute(added []net.IP, deleted []net.IP) {
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

func (s *ServiceHandler) deleteServiceEntries(entries []types.CnatTranslateEntry, oldService *LocalService) {
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

func (s *ServiceHandler) OnServiceEndpointsDelete(evt *common.ServiceEndpointsDelete) {
	serviceID := ServiceID(evt.Meta)
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

func (s *ServiceHandler) sameServiceEntries(entries []types.CnatTranslateEntry, service *LocalService) {
	for _, entry := range entries {
		if serviceState, found := s.serviceStateMap[entry.Key()]; found {
			serviceState.OwnerServiceID = service.ServiceID
			s.serviceStateMap[entry.Key()] = serviceState
		} else {
			s.log.Warnf("Cnat entry not found key=%s", entry.Key())
		}
	}
}

func (s *ServiceHandler) addServiceEntries(entries []types.CnatTranslateEntry, service *LocalService) {
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
