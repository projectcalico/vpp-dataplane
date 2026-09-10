package services

import (
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

// dsrEligible reports whether a service should use the SRv6-native (DSR) path
// instead of cnat: requires the feature gate + opt-in annotation, ClusterIP
// type, port==targetPort on every port, and pod-backed endpoints.
func (s *Server) dsrEligible(service *v1.Service, epSlices []*discoveryv1.EndpointSlice, svcInfo *serviceInfo) bool {
	gates := config.GetCalicoVppFeatureGates()
	if gates.SRv6NativeServicesEnabled == nil || !*gates.SRv6NativeServicesEnabled {
		return false
	}
	if gates.SRv6Enabled == nil || !*gates.SRv6Enabled {
		return false
	}
	if !svcInfo.srv6Native {
		return false
	}
	if service.Spec.Type != v1.ServiceTypeClusterIP {
		return false
	}
	// External/LB IPs stay on cnat; keep the whole service on cnat for consistency.
	if len(service.Spec.ExternalIPs) > 0 || len(service.Status.LoadBalancer.Ingress) > 0 {
		return false
	}
	for _, port := range service.Spec.Ports {
		tp := port.TargetPort
		if tp.Type == intstr.String { // named targetPort: can't verify port==targetPort
			s.log.Warnf("svc(dsr) %s/%s: named targetPort not supported, falling back to cnat", service.Namespace, service.Name)
			return false
		}
		if tp.IntVal != 0 && tp.IntVal != port.Port {
			s.log.Warnf("svc(dsr) %s/%s: port remap %d->%d not supported, falling back to cnat", service.Namespace, service.Name, port.Port, tp.IntVal)
			return false
		}
	}
	// Backends must be pod-backed (IP in a Calico IPAM pool); host-network
	// services (endpoint == node IP) can't be DSR-delivered, so keep them on cnat.
	if s.felixServerIpam != nil {
		for _, epslice := range epSlices {
			for _, ep := range epslice.Endpoints {
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				for _, addr := range ep.Addresses {
					ip := net.ParseIP(addr)
					if ip == nil || ip.To4() != nil {
						continue
					}
					if s.felixServerIpam.GetPrefixIPPool(common.ToMaxLenCIDR(ip)) == nil {
						s.log.Warnf("svc(dsr) %s/%s: backend %s is not pod-backed (not in an IPAM pool); falling back to cnat", service.Namespace, service.Name, addr)
						return false
					}
				}
			}
		}
	}
	return true
}

// buildDSRServices returns one common.DSRService per (IPv6) ClusterIP of a
// DSR-eligible service, carrying all of its ready pod-backed backend IPs.
func (s *Server) buildDSRServices(service *v1.Service, epSlices []*discoveryv1.EndpointSlice, svcInfo *serviceInfo) []common.DSRService {
	if !s.dsrEligible(service, epSlices, svcInfo) {
		return nil
	}
	backendSet := make(map[string]net.IP)
	for _, epslice := range epSlices {
		for _, ep := range epslice.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, addr := range ep.Addresses {
				ip := net.ParseIP(addr)
				if ip == nil || ip.To4() != nil {
					continue // IPv6 backends only for now
				}
				backendSet[ip.String()] = ip
			}
		}
	}
	backends := make([]net.IP, 0, len(backendSet))
	for _, ip := range backendSet {
		backends = append(backends, ip)
	}

	var out []common.DSRService
	for _, cip := range service.Spec.ClusterIPs {
		vip := net.ParseIP(cip)
		if vip == nil || vip.To4() != nil || vip.IsUnspecified() {
			continue // IPv6 ClusterIP only for now
		}
		out = append(out, common.DSRService{
			VIP:       vip,
			Backends:  backends,
			ServiceID: objectID(&service.ObjectMeta),
		})
	}
	return out
}

// handleDSREntries publishes add/delete events for a service's DSR entries,
// diffing against tracked state (robust to caller arg order). Deletion is
// handled in deleteServiceByName.
func (s *Server) handleDSREntries(service *LocalService, _ *LocalService) {
	if service == nil {
		return
	}
	serviceID := service.ServiceID
	desired := make(map[string]common.DSRService)
	for _, d := range service.DSREntries {
		desired[d.Key()] = d
	}
	s.reconcileDSR(serviceID, desired)
}

// reconcileDSR diffs the desired DSR entries for a service against the tracked
// set and publishes the resulting add/delete events.
func (s *Server) reconcileDSR(serviceID string, desired map[string]common.DSRService) {
	prev := s.dsrByServiceID[serviceID]

	// VIPs present before but gone now.
	for key, d := range prev {
		if _, ok := desired[key]; !ok {
			entry := d
			s.log.Infof("svc(dsr-del) %s vip=%s", entry.ServiceID, key)
			common.SendEvent(common.CalicoVppEvent{
				Type: common.ServiceDSRClusterIPDeleted,
				Old:  &entry,
			})
		}
	}
	// Always re-publish desired VIPs (consumers are idempotent); the periodic
	// informer resync thus retries any programming that previously failed.
	for _, d := range desired {
		entry := d
		s.log.Debugf("svc(dsr-add) %s vip=%s backends=%d", entry.ServiceID, entry.Key(), len(entry.Backends))
		common.SendEvent(common.CalicoVppEvent{
			Type: common.ServiceDSRClusterIPAdded,
			New:  &entry,
		})
	}

	if len(desired) == 0 {
		delete(s.dsrByServiceID, serviceID)
	} else {
		s.dsrByServiceID[serviceID] = desired
	}
}
