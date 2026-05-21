package connectivity

import (
	"context"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	govppapi "go.fd.io/govpp/api"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// isAlreadyGoneOnDelete: VPP returns NO_SUCH_INNER_FIB (-4) / UNSPECIFIED (-1)
// when the steering/policy is already absent — an idempotent delete.
func isAlreadyGoneOnDelete(err error) bool {
	if err == nil {
		return false
	}
	var vppErr govppapi.VPPApiError
	if !errors.As(err, &vppErr) {
		return false
	}
	return vppErr == govppapi.NO_SUCH_INNER_FIB || vppErr == govppapi.UNSPECIFIED
}

// NodeToPrefixes is data holder for node and traffic destination prefixes (subnets) that should end in the given node
type NodeToPrefixes struct {
	Node     net.IP
	Prefixes []ip_types.Prefix
}

// NodeToPolicies is data holder for node and SRv6 tunnel ending in the given node
type NodeToPolicies struct {
	Node       net.IP
	SRv6Tunnel []common.SRv6Tunnel
}

// srv6VppAPI is the subset of *vpplink.VppLink SRv6Provider uses, so tests can
// substitute a fake.
type srv6VppAPI interface {
	ListSRv6Localsid() ([]*types.SrLocalsid, error)
	AddSRv6Localsid(*types.SrLocalsid) error
	AddModSRv6Policy(*types.SrPolicy) error
	AddSRv6Steering(*types.SrSteer) error
	DelSRv6Steering(*types.SrSteer) error
	DelSRv6Policy(*types.SrPolicy) error
	ListSRv6Steering() ([]*types.SrSteer, error)
	SetEncapSource(net.IP) error
	RouteAdd(*types.Route) error
	RouteDel(*types.Route) error
}

// SRv6Provider is node connectivity provider that uses segment routing over IPv6 (SRv6) to connect the nodes
// For more info about SRv6, see https://datatracker.ietf.org/doc/html/rfc8986.
type SRv6Provider struct {
	*ConnectivityProviderData
	// vpp shadows the embedded ConnectivityProviderData.vpp so tests can inject
	// a fake; production wires the real *vpplink.VppLink through here.
	vpp srv6VppAPI

	// nodePrefixes is internal data holder for information from common.NodeConnectivity data
	// from common.ConnectivityAdded event
	nodePrefixes map[string]*NodeToPrefixes
	// nodePolices is internal data holder for information about SRv6 tunnel(policies)
	// from common.SRv6PolicyAdded event
	nodePolices map[string]*NodeToPolicies
	// policyIPPool is IP pool for Policy BSIDs (BSID = IPv6 address in SRv6)
	policyIPPool net.IPNet
	// localSidIPPool is IP pool for LocalSID's SIDs (SID = IPv6 address in SRv6)
	localSidIPPool net.IPNet
	// pendingBsidCleanup holds prior BSIDs not yet freeable (a steering still
	// resolves through them); drained on later SR-policy events to avoid leaks.
	pendingBsidCleanup []ip_types.IP6Address
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{
		ConnectivityProviderData: d,
		vpp:                      d.vpp,
		nodePrefixes:             make(map[string]*NodeToPrefixes),
		nodePolices:              make(map[string]*NodeToPolicies),
	}
	if *config.GetCalicoVppFeatureGates().SRv6Enabled {
		p.localSidIPPool = cnet.MustParseNetwork(config.GetCalicoVppSrv6().LocalsidPool).IPNet
		p.policyIPPool = cnet.MustParseNetwork(config.GetCalicoVppSrv6().PolicyPool).IPNet
	}

	p.log.Infof("SRv6Provider NewSRv6Provider")
	return p
}

func (p *SRv6Provider) GetSwifindexes() []uint32 {
	return []uint32{}
}

func (p *SRv6Provider) EnableDisable(isEnable bool) {
}

func (p *SRv6Provider) Enabled(cn *common.NodeConnectivity) bool {
	return *config.GetCalicoVppFeatureGates().SRv6Enabled
}

// RescanState recreates(if missing in VPP) the static parts of the SRv6 tunneling on this node:
// 1. missing locasids (possible SRv6 tunnel endpoints) if they are not existing.
// 2. source encapsulation setting (pointing to IP of this node)
func (p *SRv6Provider) RescanState() {
	p.log.Infof("SRv6Provider RescanState")

	if !*config.GetCalicoVppFeatureGates().SRv6Enabled {
		return
	}

	err := p.setEncapSource()
	if err != nil {
		p.log.Errorf("setEncapSource Error : %v", err)
	}

	localSids, err := p.vpp.ListSRv6Localsid()
	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SRv6Localsid: %v", err)
	}
	_, err = p.createLocalSidTunnels(localSids)
	if err != nil {
		p.log.Errorf("SRv6Provider Error creating SRv6Localsid: %v", err)
	}

}

func (p *SRv6Provider) CreateSRv6Tunnnel(dst net.IP, prefixDst ip_types.Prefix, policyTunnel *types.SrPolicy) (err error) {
	p.log.Infof("SRv6Provider CreateSRv6Tunnnel")

	err = p.vpp.AddModSRv6Policy(policyTunnel)
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel AddSRv6Policy %s", err)

	}
	srSteer := &types.SrSteer{
		TrafficType: types.SrSteerIPv4,
		Prefix:      prefixDst,
		Bsid:        policyTunnel.Bsid,
	}

	// Change the traffic type if is an IPv6 addr
	if vpplink.IsIP6(srSteer.Prefix.Address.ToIP()) {
		srSteer.TrafficType = types.SrSteerIPv6
	}
	err = p.vpp.AddSRv6Steering(srSteer)

	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel AddSRv6Steering %s", err)

	}

	return err
}

// AddConnectivity creates dynamic parts of SRv6 tunnel leading to node that we are adding connectivity to.
// The static parts are created in RescanState.
// This method doesn't create the needed parts in one pass, you need to call this function 3 times. Once
// with basic NodeConnectivity data(from common.ConnectivityAdded event) as is done with other connectivity
// providers, once with data of the SRv6 tunnel(common.SRv6Tunnel) (from common.SRv6PolicyAdded event)
// that ends in node that we are adding connectivity to and once for create SRv6 traffic forwarding.
// The SRv6 tunnel info is propagated from tunnel-ending node using BGP(see bgp_watcher.go and
// srv6_localsid_watcher.go). After these 3 calls (and the RescanState call)
// you get fully configured SRv6 tunnel with SR steering, SR policy, SR localsids an SRv6 traffic forwarding.
func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())

	var nodeip string
	// Set by the upsert below when it supersedes a prior BSID; freed (or queued)
	// by drainPendingBsidCleanup at function end, after the steering re-point.
	var orphanedBsid ip_types.IP6Address
	var orphanedBsidValid bool

	// processing normal NodeConnectivity data only IPv6 destination
	if vpplink.IsIP6(cn.NextHop) && !p.isSRv6TunnelInfoFromBGP(cn) {
		// destination IP can't be from policy IPPool, because this IPPool is reserved for policy BSIDs
		if p.policyIPPool.Contains(cn.Dst.IP) {
			p.log.Infof("SRv6Provider AddConnectivity no valid prefix %s", cn.Dst.String())
			return nil
		}

		// variables processing
		nodeip = cn.NextHop.String()                         // destination node IP
		prefix, err := ip_types.ParsePrefix(cn.Dst.String()) // traffic destination that should use SRv6 tunnel
		if err != nil {
			return errors.Wrapf(err, "SRv6Provider unable to parse prefix")
		}

		// Creating SRv6 traffic forwarding (this is where one call of this method finishes)
		if p.localSidIPPool.Contains(cn.Dst.IP) {
			p.log.Debugf("SRv6Provider AddConnectivity localSidIPPool prefix %s", cn.Dst.String())
			err = p.vpp.RouteAdd(&types.Route{
				Dst:   prefix.ToIPNet(),
				Paths: []types.RoutePath{{Gw: cn.NextHop.To16(), SwIfIndex: common.VppManagerInfo.GetMainSwIfIndex()}},
			})

			return err
		}

		p.log.Debugf("SRv6Provider AddConnectivity prefix %s for node %s", prefix.String(), nodeip)

		// storing info in nodePrefixes
		if p.nodePrefixes[nodeip] == nil {
			p.nodePrefixes[nodeip] = &NodeToPrefixes{
				Node:     cn.NextHop,
				Prefixes: []ip_types.Prefix{},
			}
		}
		p.nodePrefixes[nodeip].Prefixes = append(p.nodePrefixes[nodeip].Prefixes, prefix)

		// stopping processing until we have also needed SRv6 tunnel data (SRv6 policy)
		// from the destination node (BGP transportation)
		if p.nodePolices[nodeip] == nil {
			p.log.Infof("SRv6Provider no policies for %s", nodeip)
			return nil
		}

	} else if p.isSRv6TunnelInfoFromBGP(cn) && cn.Custom != nil { // getting SRv6 tunnel data from BGP

		// storing info in nodePolices
		policyData, ok := cn.Custom.(*common.SRv6Tunnel)
		if !ok {
			return fmt.Errorf("cn.Custom is not a (*common.SRv6Tunnel) %v", cn.Custom)
		}
		nodeip = policyData.Dst.String()
		if p.nodePolices[policyData.Dst.String()] == nil {
			p.nodePolices[policyData.Dst.String()] = &NodeToPolicies{
				Node:       policyData.Dst,
				SRv6Tunnel: []common.SRv6Tunnel{},
			}
		}

		p.log.Debugf("SRv6Provider new policy %s with behavior %d on node %s and priority %d", policyData.Bsid.String(), policyData.Behavior, nodeip, policyData.Priority)
		// RFC 9012 NLRI key <Distinguisher, Color, Endpoint>: same key replaces
		// the prior candidate in place (endpoint = map key), never appends.
		entry := p.nodePolices[policyData.Dst.String()]
		replaced := false
		for i := range entry.SRv6Tunnel {
			if entry.SRv6Tunnel[i].Color != policyData.Color || entry.SRv6Tunnel[i].Distinguisher != policyData.Distinguisher {
				continue
			}
			// BSID changed: hand the prior one to the deferred cleanup
			// (freed after the steering is re-pointed, never while live).
			oldBsid, oldOk := tunnelBsid(&entry.SRv6Tunnel[i])
			newBsid, newOk := tunnelBsid(policyData)
			if oldOk && newOk && oldBsid != newBsid {
				orphanedBsid = oldBsid
				orphanedBsidValid = true
			}
			entry.SRv6Tunnel[i] = *policyData
			replaced = true
			break
		}
		if !replaced {
			entry.SRv6Tunnel = append(entry.SRv6Tunnel, *policyData)
		}

		if p.nodePrefixes[nodeip] == nil {
			p.log.Debugf("SRv6Provider no prefixes for %s", nodeip)
			// Fall through so the function-end drain still runs; the
			// CreateSRv6Tunnel block below is gated on nodePrefixes != nil.
		}

	}

	// We got all needed data (normal common.NodeConnectivity and SRv6 tunnel info from tunnel-end node transported by BGP)
	// we can create dynamic parts of SRv6 tunnel (SR steering and SR policy)
	if p.nodePrefixes[nodeip] != nil {
		p.log.Debugf("SRv6Provider check new tunnel for node %s, prefixes %d", nodeip, len(p.nodePrefixes[nodeip].Prefixes))

		for _, prefix := range p.nodePrefixes[nodeip].Prefixes {
			prefixBehavior := types.SrBehaviorDT4
			if vpplink.IsIP6(prefix.Address.ToIP()) {
				prefixBehavior = types.SrBehaviorDT6
			}

			policy, err := p.getPolicyNode(nodeip, prefixBehavior)
			if err == nil && policy != nil {
				if err := p.CreateSRv6Tunnnel(p.nodePrefixes[nodeip].Node, prefix, policy); err != nil {
					p.log.Error(err)
				}
			}

		}
	}

	p.drainPendingBsidCleanup(orphanedBsid, orphanedBsidValid)
	return nil
}

// drainPendingBsidCleanup deletes queued BSIDs no steering resolves through
// (one ListSRv6Steering classifies all); still-referenced ones stay queued.
func (p *SRv6Provider) drainPendingBsidCleanup(orphanedBsid ip_types.IP6Address, orphanedBsidValid bool) {
	if orphanedBsidValid {
		p.pendingBsidCleanup = append(p.pendingBsidCleanup, orphanedBsid)
	}
	if len(p.pendingBsidCleanup) == 0 {
		return
	}
	steering, listErr := p.vpp.ListSRv6Steering()
	if listErr != nil {
		p.log.Warnf("SRv6Provider drainPendingBsidCleanup: ListSRv6Steering failed: %v; %d BSID cleanups deferred",
			listErr, len(p.pendingBsidCleanup))
		return
	}
	referenced := make(map[ip_types.IP6Address]struct{}, len(steering))
	for _, st := range steering {
		referenced[st.Bsid] = struct{}{}
	}
	queue := p.pendingBsidCleanup
	p.pendingBsidCleanup = nil
	for _, bsid := range queue {
		if _, stillSteered := referenced[bsid]; stillSteered {
			p.log.Debugf("SRv6Provider drainPendingBsidCleanup: BSID %s still steered; re-queued", bsid)
			p.pendingBsidCleanup = append(p.pendingBsidCleanup, bsid)
			continue
		}
		err := p.vpp.DelSRv6Policy(&types.SrPolicy{Bsid: bsid})
		if err == nil || isAlreadyGoneOnDelete(err) {
			p.log.Debugf("SRv6Provider drainPendingBsidCleanup: BSID %s freed: %v", bsid, err)
			continue
		}
		// Hard error: keep the BSID queued to retry on the next event.
		p.log.Warnf("SRv6Provider drainPendingBsidCleanup: BSID %s cleanup failed: %v; re-queued", bsid, err)
		p.pendingBsidCleanup = append(p.pendingBsidCleanup, bsid)
	}
}

// DelConnectivity tears down state from AddConnectivity. cn.Custom set =
// SRv6PolicyDeleted (NLRI-key teardown); cn.Dst set = ConnectivityDeleted
// (prefix steering). Per-step failures are logged, not fatal.
func (p *SRv6Provider) DelConnectivity(cn *common.NodeConnectivity) error {
	p.log.Infof("SRv6Provider DelConnectivity %s", cn.String())
	if cn.Custom != nil {
		return p.delSRPolicy(cn)
	}
	if cn.Dst.IP != nil {
		return p.delPrefixSteering(cn)
	}
	return fmt.Errorf("SRv6Provider DelConnectivity: cn has neither Custom nor Dst.IP")
}

func (p *SRv6Provider) delSRPolicy(cn *common.NodeConnectivity) error {
	policyData, ok := cn.Custom.(*common.SRv6Tunnel)
	if !ok || policyData == nil {
		return fmt.Errorf("SRv6Provider DelConnectivity: cn.Custom is not a *common.SRv6Tunnel: %T", cn.Custom)
	}
	// A withdraw may free a queued BSID; retry the drain on any return path.
	defer p.drainPendingBsidCleanup(ip_types.IP6Address{}, false)
	nodeip := policyData.Dst.String()
	entry := p.nodePolices[nodeip]
	if entry == nil {
		p.log.Infof("SRv6Provider DelConnectivity: no cached policies for endpoint %s", nodeip)
		return nil
	}

	// Match cached tunnels by <Distinguisher, Color, Endpoint> NLRI key.
	// Withdraws carry only the NLRI key (no BSID); the cached tunnel preserves
	// the BSID we installed, which is what VPP needs to delete.
	var matched []ip_types.IP6Address
	remaining := entry.SRv6Tunnel[:0]
	for _, tun := range entry.SRv6Tunnel {
		if tun.Color == policyData.Color && tun.Distinguisher == policyData.Distinguisher {
			if b, ok := tunnelBsid(&tun); ok {
				matched = append(matched, b)
			}
			continue
		}
		remaining = append(remaining, tun)
	}
	if len(matched) == 0 {
		p.log.Infof("SRv6Provider DelConnectivity: no cached policy matched endpoint=%s color=%d distinguisher=%d",
			nodeip, policyData.Color, policyData.Distinguisher)
		return nil
	}

	steering, listErr := p.vpp.ListSRv6Steering()
	if listErr != nil {
		p.log.Warnf("SRv6Provider DelConnectivity: failed to list steering: %v", listErr)
	}
	// logDel: silent on success, debug when VPP says it's already gone, warn otherwise.
	logDel := func(what string, err error) {
		if err == nil {
			return
		}
		log := p.log.Warnf
		if isAlreadyGoneOnDelete(err) {
			log = p.log.Debugf
		}
		log("SRv6Provider DelConnectivity: %s: %v", what, err)
	}

	// Track which prefixes lose their steering: after we delete this BSID,
	// the RFC 9256 candidate-path failover wants the next-best surviving
	// policy of the same behavior to take over. Re-steer happens below, after
	// the cache prune, so getPolicyNode sees the post-withdraw state.
	var orphaned []ip_types.Prefix
	for _, bsid := range matched {
		for _, st := range steering {
			if st.Bsid != bsid {
				continue
			}
			orphaned = append(orphaned, st.Prefix)
			logDel(fmt.Sprintf("DelSRv6Steering bsid=%s prefix=%s", st.Bsid, st.Prefix), p.vpp.DelSRv6Steering(st))
		}
		logDel(fmt.Sprintf("DelSRv6Policy bsid=%s", bsid), p.vpp.DelSRv6Policy(&types.SrPolicy{Bsid: bsid}))
	}

	if len(remaining) == 0 {
		delete(p.nodePolices, nodeip)
	} else {
		entry.SRv6Tunnel = remaining
	}

	// AddConnectivity only installs the highest-priority candidate per behavior;
	// lower-priority survivors are cached but absent from VPP. Track which we
	// install on demand here so multiple orphaned prefixes targeting the same
	// surviving BSID don't churn the install.
	installed := make(map[ip_types.IP6Address]struct{})
	for _, prefix := range orphaned {
		p.resteerOrphan(nodeip, prefix, installed)
	}
	return nil
}

// resteerOrphan re-points a prefix whose steering BSID just got deleted at the
// next-best surviving policy of the matching behavior on the same endpoint. The
// chosen policy may have never been installed in VPP (it was masked by the
// withdrawn higher-priority candidate), so install it on demand — guarded by
// `installed` so we install at most once per delSRPolicy call. If no candidate
// remains the prefix is left unsteered and AddConnectivity picks it up when a
// new candidate is later advertised.
func (p *SRv6Provider) resteerOrphan(nodeip string, prefix ip_types.Prefix, installed map[ip_types.IP6Address]struct{}) {
	behavior := types.SrBehaviorDT4
	if vpplink.IsIP6(prefix.Address.ToIP()) {
		behavior = types.SrBehaviorDT6
	}
	policy, err := p.getPolicyNode(nodeip, behavior)
	if err != nil || policy == nil {
		p.log.Infof("SRv6Provider DelConnectivity: no surviving policy for endpoint=%s prefix=%s behavior=%d; prefix left unsteered",
			nodeip, prefix.String(), behavior)
		return
	}
	if _, ok := installed[policy.Bsid]; !ok {
		if err := p.vpp.AddModSRv6Policy(policy); err != nil {
			p.log.Warnf("SRv6Provider DelConnectivity: AddModSRv6Policy bsid=%s for failover: %v",
				policy.Bsid.String(), err)
			return
		}
		installed[policy.Bsid] = struct{}{}
	}
	srSteer := &types.SrSteer{
		TrafficType: types.SrSteerIPv4,
		Prefix:      prefix,
		Bsid:        policy.Bsid,
	}
	if vpplink.IsIP6(prefix.Address.ToIP()) {
		srSteer.TrafficType = types.SrSteerIPv6
	}
	if err := p.vpp.AddSRv6Steering(srSteer); err != nil {
		p.log.Warnf("SRv6Provider DelConnectivity: AddSRv6Steering prefix=%s bsid=%s: %v",
			prefix.String(), policy.Bsid.String(), err)
		return
	}
	p.log.Infof("SRv6Provider DelConnectivity: re-steered prefix=%s onto surviving bsid=%s behavior=%d",
		prefix.String(), policy.Bsid.String(), behavior)
}

func (p *SRv6Provider) delPrefixSteering(cn *common.NodeConnectivity) error {
	if p.policyIPPool.Contains(cn.Dst.IP) {
		p.log.Debugf("SRv6Provider DelConnectivity skip policyIPPool prefix %s", cn.Dst.String())
		return nil
	}
	prefix, err := ip_types.ParsePrefix(cn.Dst.String())
	if err != nil {
		return errors.Wrapf(err, "SRv6Provider DelConnectivity unable to parse prefix %s", cn.Dst.String())
	}
	if p.localSidIPPool.Contains(cn.Dst.IP) {
		if delErr := p.vpp.RouteDel(&types.Route{
			Dst:   prefix.ToIPNet(),
			Paths: []types.RoutePath{{Gw: cn.NextHop.To16(), SwIfIndex: common.VppManagerInfo.GetMainSwIfIndex()}},
		}); delErr != nil {
			p.log.Warnf("SRv6Provider DelConnectivity: RouteDel localSidIPPool %s: %v", cn.Dst.String(), delErr)
		}
		return nil
	}

	nodeip := cn.NextHop.String()
	prefixKey := prefix.String()
	steering, listErr := p.vpp.ListSRv6Steering()
	if listErr != nil {
		p.log.Warnf("SRv6Provider DelConnectivity: failed to list steering: %v", listErr)
	}
	for _, st := range steering {
		if st.Prefix.String() != prefixKey {
			continue
		}
		if err := p.vpp.DelSRv6Steering(st); err != nil {
			log := p.log.Warnf
			if isAlreadyGoneOnDelete(err) {
				log = p.log.Debugf
			}
			log("SRv6Provider DelConnectivity: DelSRv6Steering prefix=%s bsid=%s: %v", st.Prefix, st.Bsid, err)
		}
	}

	if entry := p.nodePrefixes[nodeip]; entry != nil {
		remaining := entry.Prefixes[:0]
		for _, px := range entry.Prefixes {
			if px.String() != prefixKey {
				remaining = append(remaining, px)
			}
		}
		if len(remaining) == 0 {
			delete(p.nodePrefixes, nodeip)
		} else {
			entry.Prefixes = remaining
		}
	}
	return nil
}

// tunnelBsid prefers Policy.Bsid (already ip_types.IP6Address) over the net.IP
// form. Returns ok=false only for a malformed cached tunnel where neither field
// is set — caller should skip it.
func tunnelBsid(t *common.SRv6Tunnel) (ip_types.IP6Address, bool) {
	if t.Policy != nil && (t.Policy.Bsid != ip_types.IP6Address{}) {
		return t.Policy.Bsid, true
	}
	if len(t.Bsid) != 0 {
		return types.ToVppIP6Address(t.Bsid), true
	}
	return ip_types.IP6Address{}, false
}

// isSRv6TunnelInfoFromBGP checks whether given NodeConnectivity data is from BGP watcher that should pass
// SRv6 tunnel information from node where the tunnel should end
func (p *SRv6Provider) isSRv6TunnelInfoFromBGP(cn *common.NodeConnectivity) bool {
	return cn.Dst.IP == nil
}

// find the highest priority policy for a specific node
func (p *SRv6Provider) getPolicyNode(nodeip string, behavior types.SrBehavior) (policy *types.SrPolicy, err error) {
	p.log.Infof("SRv6Provider getPolicyNode node: %s, with beahvior: %d", nodeip, behavior)
	if p.nodePolices[nodeip] != nil {
		var priority uint32
		found := false
		p.log.Infof("SRv6Provider getPolicyNode: found %d tunnels for node %s", len(p.nodePolices[nodeip].SRv6Tunnel), nodeip)
		for i, tunnel := range p.nodePolices[nodeip].SRv6Tunnel {
			converted := types.FromGoBGPSrBehavior(tunnel.Behavior)
			p.log.Infof("SRv6Provider getPolicyNode: tunnel[%d] behavior=%d converted=%d want=%d match=%v policy=%v",
				i, tunnel.Behavior, converted, behavior, converted == behavior, tunnel.Policy != nil)
			// Skip a candidate with no SrPolicy object (nil-deref guard; a nil
			// Policy here does not imply not-installed-in-VPP). Strict > keeps
			// the first candidate on a priority tie.
			if tunnel.Policy == nil || converted != behavior {
				continue
			}
			if !found || tunnel.Priority > priority {
				priority = tunnel.Priority
				policy = tunnel.Policy
				found = true
			}
		}
	} else {
		p.log.Infof("SRv6Provider getPolicyNode: nodePolices[%s] is nil", nodeip)
	}
	if policy == nil {
		p.log.Infof("SRv6Provider getPolicyNode: no matching policy found")
	} else {
		p.log.Infof("SRv6Provider getPolicyNode: found policy bsid=%s", policy.Bsid.String())
	}
	return policy, err
}

func (p *SRv6Provider) setEncapSource() (err error) {
	p.log.Infof("SRv6Provider setEncapSource")
	_, nodeIP6 := p.GetNodeIPs()
	if nodeIP6 == nil {
		return fmt.Errorf("no ip6 found for node")
	}
	if err = p.vpp.SetEncapSource(*nodeIP6); err != nil {
		p.log.Errorf("SRv6Provider setEncapSource: %v", err)
		return errors.Wrapf(err, "SRv6Provider setEncapSource")
	}
	p.log.Debugf("SRv6Provider setEncapSource with IP6 %s", nodeIP6.String())
	return err
}

func (p *SRv6Provider) createLocalSidTunnels(currentLocalSids []*types.SrLocalsid) (localSids []*types.SrLocalsid, err error) {
	p.log.Infof("SRv6Provider createLocalSidTunnels")
	endDt4Exist := false
	endDt6Exist := false
	for _, localSid := range currentLocalSids {
		p.log.Debugf("Found existing SRv6Localsid: %s", localSid.String())

		if localSid.Behavior == types.SrBehaviorDT6 && localSid.FibTable == 0 {
			endDt6Exist = true
		}

		if localSid.Behavior == types.SrBehaviorDT4 && localSid.FibTable == 0 {
			endDt4Exist = true
		}
	}
	if !endDt4Exist {
		if localSidDT4, err := p.setEndDT(4); err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT4: %v", err)
		} else {
			localSids = append(localSids, localSidDT4)
		}
	}

	if !endDt6Exist {
		if localSidDT6, err := p.setEndDT(6); err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT6: %v", err)
		} else {
			localSids = append(localSids, localSidDT6)
		}
	}
	return localSids, err
}

// Add a new SRLocalSid with end.DT4 or end.DT6 behavior
func (p *SRv6Provider) setEndDT(typeDT int) (newLocalSid *types.SrLocalsid, err error) {
	p.log.Infof("SRv6Provider setLocalsid setEndDT%d", typeDT)

	var behavior types.SrBehavior
	switch typeDT {
	case 4:
		behavior = types.SrBehaviorDT4
	case 6:
		behavior = types.SrBehaviorDT6
	}

	poolLocalSIDName := "sr-localsids-pool-" + *config.NodeName
	newLocalSidAddr, err := p.getSidFromPool(poolLocalSIDName)

	if err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSidAddr")
		return nil, errors.Wrapf(err, "SRv6Provider  Error getSidFromPool")
	}
	p.log.Infof("SRv6Provider new LocalSid ip %s", newLocalSidAddr.String())
	newLocalSid = &types.SrLocalsid{
		Localsid: newLocalSidAddr,
		EndPsp:   false,
		FibTable: 0,
		Behavior: behavior,
	}
	if err = p.vpp.AddSRv6Localsid(newLocalSid); err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSid")
		return nil, errors.Wrapf(err, "SRv6Provider Error adding LocalSid")
	}

	return newLocalSid, err
}

func (p *SRv6Provider) getSidFromPool(poolName string) (newSidAddr ip_types.IP6Address, err error) {
	ippool, err := p.Clientv3().IPPools().Get(context.Background(), poolName, options.GetOptions{})
	if err != nil || ippool == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error getSidFromPool")
	}

	poolIPNet := []cnet.IPNet{cnet.MustParseNetwork(ippool.Spec.CIDR)}
	_, newSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:        1,
		IPv6Pools:   poolIPNet,
		IntendedUse: "Tunnel",
	})
	if err != nil || newSids == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error getSidFromPool")
	}

	newSidAddr = types.ToVppIP6Address(newSids.IPs[0].IP)

	return newSidAddr, nil
}
