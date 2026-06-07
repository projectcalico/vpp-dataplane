package cni

import (
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// dsrVIPState tracks a DSR ClusterIP's shared PodVRFIndex delivery route and the
// local pods that currently have the VIP programmed (lo bind + uRPF allow).
// boundPods drives cleanup: a pod stays until its binding is removed or it's gone.
type dsrVIPState struct {
	vip       net.IP
	delivery  *types.Route
	boundPods map[string]bool
}

func (s *Server) handleDSRServiceAdded(svc *common.DSRService) {
	if svc == nil || svc.VIP == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.dsrDesired[svc.VIP.String()] = svc
	s.reconcileDSRVIPs()
}

func (s *Server) handleDSRServiceDeleted(svc *common.DSRService) {
	if svc == nil || svc.VIP == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.dsrDesired, svc.VIP.String())
	s.reconcileDSRVIPs()
}

// reconcileDSRVIPs drives installed DSR VIP state toward the desired set,
// retrying failed installs/removals. Invoked on DSR events, resync, pod add/del.
// Caller holds s.lock.
func (s *Server) reconcileDSRVIPs() {
	for _, svc := range s.dsrDesired {
		s.programDSRVIP(svc)
	}
	for key := range s.dsrVIPs {
		if _, ok := s.dsrDesired[key]; !ok {
			s.teardownDSRVIP(key)
		}
	}
}

// programDSRVIP binds the VIP on local backend pods (lo + uRPF), unbinds
// departed ones, and reconciles the PodVRFIndex ECMP delivery route. Holds s.lock.
func (s *Server) programDSRVIP(svc *common.DSRService) {
	vipKey := svc.VIP.String()
	prev := s.dsrVIPs[vipKey]
	boundPods := map[string]bool{}
	if prev != nil {
		for ip := range prev.boundPods {
			boundPods[ip] = true
		}
	}

	desiredLocal := map[string]bool{}
	var deliveryPaths []types.RoutePath
	for _, beIP := range svc.Backends {
		podSpec := s.findLocalPodByIP(beIP)
		if podSpec == nil || podSpec.TunTapSwIfIndex == vpplink.InvalidSwIfIndex {
			continue // not a local tun-backed pod
		}
		desiredLocal[beIP.String()] = true
		if err := s.bindVIPInPod(podSpec, svc.VIP, true /* add */); err != nil {
			s.log.Errorf("cni(dsr) bind vip=%s pod=%s: %v", svc.VIP, beIP, err)
		}
		if err := s.dsrRPFRoute(podSpec, svc.VIP, true /* add */); err != nil {
			s.log.Errorf("cni(dsr) rpf add vip=%s pod=%s: %v", svc.VIP, beIP, err)
		}
		boundPods[beIP.String()] = true
		deliveryPaths = append(deliveryPaths, types.RoutePath{
			SwIfIndex: podSpec.TunTapSwIfIndex,
			Gw:        beIP,
		})
	}

	// Unbind pods no longer backing the service; keep ones whose cleanup fails so
	// a departed-but-running pod can't keep answering as / uRPF-spoofing the VIP.
	for ipStr := range boundPods {
		if desiredLocal[ipStr] {
			continue
		}
		if s.cleanupDSRPod(ipStr, svc.VIP) {
			delete(boundPods, ipStr)
		}
	}

	st := &dsrVIPState{vip: svc.VIP, boundPods: boundPods}
	st.delivery = s.updateDeliveryRoute(svc.VIP, prev, deliveryPaths)
	// Drop the entry only once the route is gone AND no pod cleanup is pending.
	if st.delivery == nil && len(boundPods) == 0 {
		delete(s.dsrVIPs, vipKey)
		return
	}
	s.dsrVIPs[vipKey] = st
	s.log.Debugf("cni(dsr) vip=%s local backends=%d bound=%d", svc.VIP, len(desiredLocal), len(boundPods))
}

// teardownDSRVIP removes all DSR state for an undesired VIP, retaining anything
// whose removal fails for the next reconcile. Caller holds s.lock.
func (s *Server) teardownDSRVIP(key string) {
	st := s.dsrVIPs[key]
	if st == nil {
		return
	}
	st.delivery = s.updateDeliveryRoute(st.vip, st, nil /* no paths */)
	for ipStr := range st.boundPods {
		if s.cleanupDSRPod(ipStr, st.vip) {
			delete(st.boundPods, ipStr)
		}
	}
	if st.delivery == nil && len(st.boundPods) == 0 {
		delete(s.dsrVIPs, key)
	}
}

// cleanupDSRPod removes a pod's VIP binding (lo) + uRPF allow. Returns true when
// done (pod gone, or both removals succeeded), false to retry.
func (s *Server) cleanupDSRPod(ipStr string, vip net.IP) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	podSpec := s.findLocalPodByIP(ip)
	if podSpec == nil {
		return true // pod gone; netns + per-pod RPF VRF auto-cleaned
	}
	ok := true
	if err := s.bindVIPInPod(podSpec, vip, false /* del */); err != nil {
		s.log.Errorf("cni(dsr) unbind vip=%s pod=%s: %v", vip, ip, err)
		ok = false
	}
	if err := s.dsrRPFRoute(podSpec, vip, false /* del */); err != nil {
		s.log.Errorf("cni(dsr) rpf del vip=%s pod=%s: %v", vip, ip, err)
		ok = false
	}
	return ok
}

// updateDeliveryRoute reconciles the PodVRFIndex delivery route for a VIP to the
// given paths (unchanged = keep; changed = del+add; none = del), retaining the
// installed route on VPP failure so the next reconcile retries.
func (s *Server) updateDeliveryRoute(vip net.IP, prev *dsrVIPState, paths []types.RoutePath) *types.Route {
	if prev != nil && prev.delivery != nil {
		if len(paths) > 0 && samePaths(prev.delivery.Paths, paths) {
			return prev.delivery
		}
		if err := s.vpp.RouteDel(prev.delivery); err != nil {
			s.log.Errorf("cni(dsr) del delivery route vip=%s: %v", vip, err)
			return prev.delivery // keep old; retry replacement next reconcile
		}
	}
	if len(paths) == 0 {
		return nil
	}
	route := &types.Route{
		Dst:   common.ToMaxLenCIDR(vip),
		Paths: paths,
		Table: common.PodVRFIndex,
	}
	if err := s.vpp.RouteAdd(route); err != nil {
		s.log.Errorf("cni(dsr) add delivery route vip=%s: %v", vip, err)
		return nil // retry add next reconcile
	}
	return route
}

// samePaths reports whether two route path sets are equal (order-independent).
func samePaths(a, b []types.RoutePath) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		idx uint32
		gw  string
	}
	m := make(map[key]int)
	for _, p := range a {
		m[key{p.SwIfIndex, p.Gw.String()}]++
	}
	for _, p := range b {
		m[key{p.SwIfIndex, p.Gw.String()}]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// findLocalPodByIP returns the local pod spec whose container IP equals ip.
func (s *Server) findLocalPodByIP(ip net.IP) *model.LocalPodSpec {
	for key := range s.podInterfaceMap {
		spec := s.podInterfaceMap[key]
		for _, cip := range spec.GetContainerIPs() {
			if cip.IP.Equal(ip) {
				return &spec
			}
		}
	}
	return nil
}

// bindVIPInPod adds/removes the VIP on the pod's lo inside its netns, checking
// presence first so add/del are no-ops (not spurious errors) when already done.
func (s *Server) bindVIPInPod(podSpec *model.LocalPodSpec, vip net.IP, add bool) error {
	if podSpec.NetnsName == "" {
		return nil
	}
	return ns.WithNetNSPath(podSpec.NetnsName, func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		addrs, err := netlink.AddrList(lo, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		present := false
		for _, a := range addrs {
			if a.IP.Equal(vip) {
				present = true
				break
			}
		}
		addr := &netlink.Addr{IPNet: common.ToMaxLenCIDR(vip)}
		if add {
			if present {
				return nil
			}
			return netlink.AddrAdd(lo, addr)
		}
		if present {
			return netlink.AddrDel(lo, addr)
		}
		return nil
	})
}

// dsrRPFRoute adds/removes a VIP route in the pod's RPF VRF so loose uRPF accepts
// (add) / rejects (del) a reply sourced from the VIP. RouteDel is idempotent.
func (s *Server) dsrRPFRoute(podSpec *model.LocalPodSpec, vip net.IP, add bool) error {
	vipNet := common.ToMaxLenCIDR(vip)
	rpfVrfID := podSpec.GetRPFVrfID(vpplink.IPFamilyFromIPNet(vipNet))
	if rpfVrfID == vpplink.InvalidID {
		return nil
	}
	gw := podContainerIPForVIP(podSpec, vip)
	if gw == nil {
		return nil
	}
	paths := []types.RoutePath{{SwIfIndex: podSpec.TunTapSwIfIndex, Gw: gw}}
	if podSpec.MemifSwIfIndex != vpplink.InvalidSwIfIndex {
		paths = append(paths, types.RoutePath{SwIfIndex: podSpec.MemifSwIfIndex, Gw: gw})
	}
	route := &types.Route{Dst: vipNet, Paths: paths, Table: rpfVrfID}
	if add {
		return s.vpp.RouteAdd(route)
	}
	return s.vpp.RouteDel(route)
}

// podContainerIPForVIP returns the pod's container IP of the same family as vip.
func podContainerIPForVIP(podSpec *model.LocalPodSpec, vip net.IP) net.IP {
	wantV6 := vip.To4() == nil
	for _, cip := range podSpec.GetContainerIPs() {
		if (cip.IP.To4() == nil) == wantV6 {
			return cip.IP
		}
	}
	return nil
}
