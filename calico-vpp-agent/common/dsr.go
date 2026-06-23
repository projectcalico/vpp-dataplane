package common

import "net"

// DSRService describes an SRv6-native / NAT-less (DSR) ClusterIP service,
// published by the services server and consumed by the SRv6 and CNI servers.
type DSRService struct {
	VIP       net.IP   // service ClusterIP
	Backends  []net.IP // all pod-backed endpoint IPs (local + remote)
	ServiceID string   // namespace/name, for logging
}

// Key identifies a DSR service by its VIP.
func (d *DSRService) Key() string {
	if d == nil || d.VIP == nil {
		return ""
	}
	return d.VIP.String()
}
