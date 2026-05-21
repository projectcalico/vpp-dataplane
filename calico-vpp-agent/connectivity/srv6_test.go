package connectivity

import (
	"io"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	govppapi "go.fd.io/govpp/api"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// fakeSRv6VPP records every srv6VppAPI call so tests can assert what reached
// the dataplane and seed ListSRv6Steering output. callLog records the
// interleaving across methods so ordering-sensitive tests can verify e.g.
// "AddSRv6Steering happened before DelSRv6Policy".
type fakeSRv6VPP struct {
	steering []*types.SrSteer

	addModPolicy []*types.SrPolicy
	delPolicy    []*types.SrPolicy
	addSteering  []*types.SrSteer
	delSteering  []*types.SrSteer
	routeAdd     []*types.Route
	routeDel     []*types.Route
	callLog      []string

	listSteeringErr error
	addModPolicyErr error
	delSteeringErr  error
	delPolicyErr    error
}

func (f *fakeSRv6VPP) ListSRv6Localsid() ([]*types.SrLocalsid, error) { return nil, nil }
func (f *fakeSRv6VPP) AddSRv6Localsid(*types.SrLocalsid) error        { return nil }
func (f *fakeSRv6VPP) SetEncapSource(net.IP) error                    { return nil }
func (f *fakeSRv6VPP) RouteAdd(r *types.Route) error                  { f.routeAdd = append(f.routeAdd, r); return nil }
func (f *fakeSRv6VPP) RouteDel(r *types.Route) error                  { f.routeDel = append(f.routeDel, r); return nil }

func (f *fakeSRv6VPP) AddModSRv6Policy(p *types.SrPolicy) error {
	f.addModPolicy = append(f.addModPolicy, p)
	f.callLog = append(f.callLog, "AddModSRv6Policy:"+p.Bsid.String())
	return f.addModPolicyErr
}
func (f *fakeSRv6VPP) DelSRv6Policy(p *types.SrPolicy) error {
	f.delPolicy = append(f.delPolicy, p)
	f.callLog = append(f.callLog, "DelSRv6Policy:"+p.Bsid.String())
	return f.delPolicyErr
}
func (f *fakeSRv6VPP) AddSRv6Steering(s *types.SrSteer) error {
	f.addSteering = append(f.addSteering, s)
	f.callLog = append(f.callLog, "AddSRv6Steering:"+s.Bsid.String())
	return nil
}
func (f *fakeSRv6VPP) DelSRv6Steering(s *types.SrSteer) error {
	f.delSteering = append(f.delSteering, s)
	f.callLog = append(f.callLog, "DelSRv6Steering:"+s.Bsid.String())
	return f.delSteeringErr
}
func (f *fakeSRv6VPP) ListSRv6Steering() ([]*types.SrSteer, error) {
	return f.steering, f.listSteeringErr
}

func newTestProvider(fake *fakeSRv6VPP) *SRv6Provider {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &SRv6Provider{
		ConnectivityProviderData: &ConnectivityProviderData{log: logrus.NewEntry(logger)},
		vpp:                      fake,
		nodePrefixes:             make(map[string]*NodeToPrefixes),
		nodePolices:              make(map[string]*NodeToPolicies),
	}
}

func mustBsid(t *testing.T, s string) ip_types.IP6Address {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To16() == nil {
		t.Fatalf("invalid ipv6 %q", s)
	}
	return types.ToVppIP6Address(ip)
}

func mustPrefix(t *testing.T, s string) ip_types.Prefix {
	t.Helper()
	pr, err := ip_types.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return pr
}

// ---------- tunnelBsid ----------

func TestTunnelBsid(t *testing.T) {
	policyBsid := mustBsid(t, "cafe::1")
	netBsid := net.ParseIP("cafe::2")

	cases := []struct {
		name    string
		tun     common.SRv6Tunnel
		wantOK  bool
		wantStr string
	}{
		{"policy wins", common.SRv6Tunnel{Policy: &types.SrPolicy{Bsid: policyBsid}, Bsid: netBsid}, true, policyBsid.String()},
		{"net.IP fallback", common.SRv6Tunnel{Bsid: netBsid}, true, types.ToVppIP6Address(netBsid).String()},
		{"policy with zero bsid falls back to net.IP", common.SRv6Tunnel{Policy: &types.SrPolicy{}, Bsid: netBsid}, true, types.ToVppIP6Address(netBsid).String()},
		{"neither set", common.SRv6Tunnel{}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tunnelBsid(&tc.tun)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.String() != tc.wantStr {
				t.Fatalf("bsid = %s, want %s", got.String(), tc.wantStr)
			}
		})
	}
}

// ---------- delSRPolicy ----------

func TestDelSRPolicy_TypeAssertError(t *testing.T) {
	p := newTestProvider(&fakeSRv6VPP{})
	cn := &common.NodeConnectivity{Custom: "not a tunnel"}
	if err := p.delSRPolicy(cn); err == nil {
		t.Fatal("expected error for non-SRv6Tunnel Custom")
	}
}

func TestDelSRPolicy_NoCache(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	dst := net.ParseIP("fd00:1::11")
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 4}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.delPolicy)+len(fake.delSteering) > 0 {
		t.Fatalf("expected no VPP calls; got delPolicy=%d delSteering=%d", len(fake.delPolicy), len(fake.delSteering))
	}
}

func TestDelSRPolicy_NLRIKeyMismatchLeavesSiblingsAlone(t *testing.T) {
	// Two cached tunnels for the same endpoint, different NLRI keys. Withdrawing
	// one (color=4) must not touch the other (color=6).
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	dst := net.ParseIP("fd00:1::11")
	dt4Bsid := mustBsid(t, "cafe::4")
	dt6Bsid := mustBsid(t, "cafe::6")
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 4, Policy: &types.SrPolicy{Bsid: dt4Bsid}, Priority: 100},
			{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: dt6Bsid}, Priority: 100},
		},
	}
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 4}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != dt4Bsid {
		t.Fatalf("expected exactly DelSRv6Policy(dt4); got %+v", fake.delPolicy)
	}
	remaining := p.nodePolices[dst.String()].SRv6Tunnel
	if len(remaining) != 1 || remaining[0].Color != 6 {
		t.Fatalf("expected dt6 sibling to survive; got %+v", remaining)
	}
}

func TestDelSRPolicy_NoMatch(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	dst := net.ParseIP("fd00:1::11")
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 4, Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::4")}},
		},
	}
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 99}} // unknown color
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.delPolicy)+len(fake.delSteering) > 0 {
		t.Fatalf("expected no VPP calls; got delPolicy=%d delSteering=%d", len(fake.delPolicy), len(fake.delSteering))
	}
}

func TestDelSRPolicy_DeletesPolicyAndAssociatedSteering(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::4")
	otherBsid := mustBsid(t, "cafe::dead") // unrelated steering, must survive
	prefixA := mustPrefix(t, "fd20::aaaa/128")
	prefixB := mustPrefix(t, "fd20::bbbb/128")
	prefixC := mustPrefix(t, "fd20::cccc/128")

	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: bsid, Prefix: prefixA, TrafficType: types.SrSteerIPv6},
			{Bsid: bsid, Prefix: prefixB, TrafficType: types.SrSteerIPv6},
			{Bsid: otherBsid, Prefix: prefixC, TrafficType: types.SrSteerIPv6},
		},
	}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node:       dst,
		SRv6Tunnel: []common.SRv6Tunnel{{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: bsid}}},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	if len(fake.delSteering) != 2 {
		t.Fatalf("expected 2 steering deletions; got %d", len(fake.delSteering))
	}
	for _, st := range fake.delSteering {
		if st.Bsid != bsid {
			t.Fatalf("DelSRv6Steering targeted wrong BSID %s, want %s", st.Bsid.String(), bsid.String())
		}
	}
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != bsid {
		t.Fatalf("DelSRv6Policy wrong: %+v", fake.delPolicy)
	}
	if _, ok := p.nodePolices[dst.String()]; ok {
		t.Fatalf("expected nodePolices entry to be removed")
	}
}

// Codex round #2 + #3 regression: withdrawing the top-priority candidate must
// (a) re-steer orphaned prefixes onto the surviving lower-priority candidate
// and (b) install that candidate in VPP on demand, since AddConnectivity never
// pushed it during normal operation.
func TestDelSRPolicy_FailoverOntoSurvivingCandidate(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	winnerBsid := mustBsid(t, "cafe::aa")
	loserBsid := mustBsid(t, "cafe::bb")
	prefixA := mustPrefix(t, "fd20::aaaa/128")
	prefixB := mustPrefix(t, "fd20::bbbb/128")

	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: winnerBsid, Prefix: prefixA, TrafficType: types.SrSteerIPv6},
			{Bsid: winnerBsid, Prefix: prefixB, TrafficType: types.SrSteerIPv6},
		},
	}
	p := newTestProvider(fake)
	// Both candidates DT6 (uint8(SRv6Behavior_END_DT6) == 18 in gobgp). Use the
	// raw uint that types.FromGoBGPSrBehavior maps to types.SrBehaviorDT6.
	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: winnerBsid}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 50, Policy: &types.SrPolicy{Bsid: loserBsid}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	// Top candidate teardown
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != winnerBsid {
		t.Fatalf("DelSRv6Policy: got %+v", fake.delPolicy)
	}
	if len(fake.delSteering) != 2 {
		t.Fatalf("expected 2 steering deletes; got %d", len(fake.delSteering))
	}
	// On-demand install of the surviver, once even for multiple orphaned prefixes
	if len(fake.addModPolicy) != 1 || fake.addModPolicy[0].Bsid != loserBsid {
		t.Fatalf("expected one AddModSRv6Policy(loser); got %+v", fake.addModPolicy)
	}
	// Re-steering for each orphaned prefix
	if len(fake.addSteering) != 2 {
		t.Fatalf("expected 2 AddSRv6Steering calls; got %d", len(fake.addSteering))
	}
	for _, st := range fake.addSteering {
		if st.Bsid != loserBsid {
			t.Fatalf("AddSRv6Steering retargeted wrong BSID %s, want %s", st.Bsid.String(), loserBsid.String())
		}
	}
	// Surviver remains in cache
	rem := p.nodePolices[dst.String()].SRv6Tunnel
	if len(rem) != 1 || rem[0].Distinguisher != 1 {
		t.Fatalf("expected loser to survive in cache; got %+v", rem)
	}
}

func TestDelSRPolicy_NoSurvivingCandidateLeavesPrefixUnsteered(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::4")
	prefix := mustPrefix(t, "fd20::1/128")
	fake := &fakeSRv6VPP{steering: []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}}}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node:       dst,
		SRv6Tunnel: []common.SRv6Tunnel{{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: bsid}}},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.addSteering) != 0 || len(fake.addModPolicy) != 0 {
		t.Fatalf("expected no re-steer / install when no surviving candidate; got addSteering=%d addModPolicy=%d", len(fake.addSteering), len(fake.addModPolicy))
	}
}

// ---------- delPrefixSteering ----------

func TestDelPrefixSteering_SkipsPolicyIPPool(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	_, ipNet, _ := net.ParseCIDR("cafe::/64")
	p.policyIPPool = *ipNet
	cn := &common.NodeConnectivity{
		Dst:     net.IPNet{IP: net.ParseIP("cafe::1"), Mask: net.CIDRMask(128, 128)},
		NextHop: net.ParseIP("fd00:1::11"),
	}
	if err := p.delPrefixSteering(cn); err != nil {
		t.Fatalf("delPrefixSteering: %v", err)
	}
	if len(fake.delSteering)+len(fake.routeDel) > 0 {
		t.Fatal("expected no VPP calls for policy-pool address")
	}
}

func TestDelPrefixSteering_NormalPrefixDeletesSteeringAndPrunesCache(t *testing.T) {
	prefix := mustPrefix(t, "fd20::aaaa/128")
	other := mustPrefix(t, "fd20::bbbb/128")
	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: mustBsid(t, "cafe::4"), Prefix: prefix, TrafficType: types.SrSteerIPv6},
			{Bsid: mustBsid(t, "cafe::4"), Prefix: other, TrafficType: types.SrSteerIPv6},
		},
	}
	p := newTestProvider(fake)
	node := net.ParseIP("fd00:1::11")
	p.nodePrefixes[node.String()] = &NodeToPrefixes{Node: node, Prefixes: []ip_types.Prefix{prefix, other}}
	cn := &common.NodeConnectivity{
		Dst:     net.IPNet{IP: net.ParseIP("fd20::aaaa"), Mask: net.CIDRMask(128, 128)},
		NextHop: node,
	}
	if err := p.delPrefixSteering(cn); err != nil {
		t.Fatalf("delPrefixSteering: %v", err)
	}
	if len(fake.delSteering) != 1 {
		t.Fatalf("expected exactly one DelSRv6Steering; got %d", len(fake.delSteering))
	}
	if fake.delSteering[0].Prefix.String() != prefix.String() {
		t.Fatalf("DelSRv6Steering targeted wrong prefix %s, want %s", fake.delSteering[0].Prefix.String(), prefix.String())
	}
	remaining := p.nodePrefixes[node.String()].Prefixes
	if len(remaining) != 1 || remaining[0].String() != other.String() {
		t.Fatalf("expected sibling prefix to survive cache prune; got %+v", remaining)
	}
}

// ---------- DelConnectivity dispatcher ----------

// Re-advertising an SR Policy with the SAME NLRI key (Color, Distinguisher,
// Endpoint) must REPLACE the cached candidate in-place, not append a duplicate.
// Without this, BGP path refresh would silently grow the cache and delSRPolicy
// would iterate the same BSID multiple times — the second pass hits VPP with
// an already-gone steering / policy and used to warn with NO_SUCH_INNER_FIB
// and UNSPECIFIED.
func TestAddConnectivity_ReAdvertiseSameNLRIKeyReplacesInPlace(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	bsidA := mustBsid(t, "cafe::aaa")
	bsidB := mustBsid(t, "cafe::bbb")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	// First advertisement.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      100,
			Policy:        &types.SrPolicy{Bsid: bsidA},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (first): %v", err)
	}

	// Re-advertisement with same NLRI key but different attrs (e.g. new BSID
	// after a path refresh). RFC 9252 says this must REPLACE the prior entry.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      150,
			Policy:        &types.SrPolicy{Bsid: bsidB},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (second): %v", err)
	}

	cache := p.nodePolices[dst.String()].SRv6Tunnel
	if len(cache) != 1 {
		t.Fatalf("expected cache to dedup to 1 entry; got %d (%+v)", len(cache), cache)
	}
	if cache[0].Priority != 150 || cache[0].Policy.Bsid != bsidB {
		t.Fatalf("expected re-advertisement to replace in place (prio=150, bsid=%s); got prio=%d bsid=%s",
			bsidB.String(), cache[0].Priority, cache[0].Policy.Bsid.String())
	}
}

// Re-advertising with the SAME NLRI key but a DIFFERENT BSID (BGP path
// refresh updates path attributes including the BSID TLV) must tear down the
// prior BSID in VPP. Otherwise the old SR Policy stays installed with no cache
// reference, and a later withdraw — matched against only the new BSID — leaks
// it permanently.
func TestAddConnectivity_BsidChangeOnUpsertCleansUpOldBsid(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	// First advertisement: cached, no VPP install (no nodePrefixes wired up
	// for the test — we just exercise the cache + cleanup path).
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      100,
			Policy:        &types.SrPolicy{Bsid: oldBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (first): %v", err)
	}
	if len(fake.delPolicy) != 0 {
		t.Fatalf("expected no DelSRv6Policy on first advertisement; got %+v", fake.delPolicy)
	}

	// Re-advertisement with same NLRI key but new BSID.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      100,
			Policy:        &types.SrPolicy{Bsid: newBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (second): %v", err)
	}

	// Old BSID must be torn down so it doesn't leak.
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != oldBsid {
		t.Fatalf("expected exactly one DelSRv6Policy(oldBsid=%s) on BSID change; got %+v",
			oldBsid.String(), fake.delPolicy)
	}

	// Cache holds only the new candidate.
	cache := p.nodePolices[dst.String()].SRv6Tunnel
	if len(cache) != 1 || cache[0].Policy.Bsid != newBsid {
		t.Fatalf("expected cache to hold only new BSID %s; got %+v", newBsid.String(), cache)
	}
}

// When the upsert changes the BSID AND prefixes are wired up for the endpoint,
// the steering MUST be re-pointed at the new BSID BEFORE the old SR Policy is
// deleted. Otherwise VPP's steering hash holds steer_pl->sr_policy = freed
// pool index for the duration of the gap and packets transiting the steering
// land on undefined state. Verified by asserting the call sequence.
func TestAddConnectivity_BsidChangeCleansUpAfterRePoint(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")
	prefix := mustPrefix(t, "fd20::5506:688f:1e5:6f80/122")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	// Pre-populate nodePrefixes so CreateSRv6Tunnel runs on each AddConnectivity.
	p.nodePrefixes[dst.String()] = &NodeToPrefixes{Node: dst, Prefixes: []ip_types.Prefix{prefix}}

	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 100,
			Policy: &types.SrPolicy{Bsid: oldBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (old): %v", err)
	}

	// Reset call log so we observe only the upsert's calls.
	fake.callLog = nil

	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 100,
			Policy: &types.SrPolicy{Bsid: newBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (new): %v", err)
	}

	addNewSteer := -1
	delOld := -1
	for i, op := range fake.callLog {
		if op == "AddSRv6Steering:"+newBsid.String() && addNewSteer == -1 {
			addNewSteer = i
		}
		if op == "DelSRv6Policy:"+oldBsid.String() && delOld == -1 {
			delOld = i
		}
	}
	if addNewSteer == -1 {
		t.Fatalf("expected AddSRv6Steering(newBsid=%s) in call log; got %v", newBsid.String(), fake.callLog)
	}
	if delOld == -1 {
		t.Fatalf("expected DelSRv6Policy(oldBsid=%s) in call log; got %v", oldBsid.String(), fake.callLog)
	}
	if !(addNewSteer < delOld) {
		t.Fatalf("AddSRv6Steering(new) must precede DelSRv6Policy(old); got log %v (newSteer@%d, delOld@%d)",
			fake.callLog, addNewSteer, delOld)
	}
}

// Failure mode: CreateSRv6Tunnel below the upsert can fail (getPolicyNode
// returned nil, AddModSRv6Policy errored, AddSRv6Steering errored), leaving
// the steering still resolving through the prior BSID. The deferred cleanup
// MUST NOT delete that BSID — VPP's sr_policy entry is still in use by a live
// steering. Simulated here by seeding ListSRv6Steering with an entry that
// continues to point at the old BSID after the upsert.
func TestAddConnectivity_BsidChangeSkipsCleanupWhenStillReferenced(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")
	prefix := mustPrefix(t, "fd20::5506:688f:1e5:6f80/122")

	// fake.steering reports what ListSRv6Steering returns. By leaving the
	// pre-existing entry pointing at oldBsid we simulate VPP's view after a
	// failed AddSRv6Steering — steer_pl->sr_policy never got re-pointed.
	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{{Bsid: oldBsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
	}
	p := newTestProvider(fake)

	// Make CreateSRv6Tunnel a no-op for this test by not wiring nodePrefixes;
	// the defer should still consult ListSRv6Steering before deleting.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: oldBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (old): %v", err)
	}
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: newBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (new): %v", err)
	}

	for _, p := range fake.delPolicy {
		if p.Bsid == oldBsid {
			t.Fatalf("DelSRv6Policy(oldBsid=%s) must NOT fire while steering still resolves through it; got call log %v",
				oldBsid.String(), fake.callLog)
		}
	}
}

// Eventual consistency: when the prior BSID couldn't be released on the
// first upsert (steering still referenced it), it must NOT be silently
// dropped from the cache. The next SR-policy event must re-attempt the
// cleanup; once VPP reports the BSID is no longer steered, the deferred
// DelSRv6Policy fires. Without the pendingBsidCleanup queue, the upsert
// would replace the cache entry, lose the prior BSID reference, and leak
// the SR Policy in VPP forever.
func TestAddConnectivity_BsidChangePendingRetryOnNextEvent(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")
	otherBsid := mustBsid(t, "cafe::bbb")
	prefix := mustPrefix(t, "fd20::5506:688f:1e5:6f80/122")

	// First upsert leaves OLD still referenced (re-point "failed").
	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{{Bsid: oldBsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
	}
	p := newTestProvider(fake)

	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: oldBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (old): %v", err)
	}
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: newBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (new): %v", err)
	}

	// After the first upsert, OLD should be queued — VPP still steers it.
	if len(p.pendingBsidCleanup) != 1 || p.pendingBsidCleanup[0] != oldBsid {
		t.Fatalf("expected pendingBsidCleanup=[%s] after first upsert; got %v",
			oldBsid.String(), p.pendingBsidCleanup)
	}
	for _, pol := range fake.delPolicy {
		if pol.Bsid == oldBsid {
			t.Fatalf("DelSRv6Policy(oldBsid) must not fire while steering still resolves through it; call log %v", fake.callLog)
		}
	}

	// Simulate VPP catching up: the steering is now repointed at otherBsid,
	// freeing OLD for cleanup.
	fake.steering = []*types.SrSteer{{Bsid: otherBsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}}

	// A subsequent SR-policy event (different NLRI key, not related to OLD)
	// must drain the pending queue and finally release OLD in VPP.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 99, Priority: 50,
			Policy: &types.SrPolicy{Bsid: otherBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (third event): %v", err)
	}

	if len(p.pendingBsidCleanup) != 0 {
		t.Fatalf("expected pendingBsidCleanup to drain to empty; got %v", p.pendingBsidCleanup)
	}
	sawOldCleanup := false
	for _, pol := range fake.delPolicy {
		if pol.Bsid == oldBsid {
			sawOldCleanup = true
			break
		}
	}
	if !sawOldCleanup {
		t.Fatalf("expected DelSRv6Policy(oldBsid=%s) on retry; got call log %v", oldBsid.String(), fake.callLog)
	}
}

// Re-advertising the SAME NLRI key with the SAME BSID (only priority or SID
// list changed) must NOT trigger cleanup — there is nothing to clean up.
// Guards against the BSID-change cleanup over-firing.
func TestAddConnectivity_SameBsidOnUpsertSkipsCleanup(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	bsid := mustBsid(t, "cafe::aaa")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	for _, prio := range []uint32{100, 150} {
		if err := p.AddConnectivity(&common.NodeConnectivity{
			NextHop: dst,
			Custom: &common.SRv6Tunnel{
				Dst:           dst,
				Color:         6,
				Distinguisher: 1,
				Priority:      prio,
				Policy:        &types.SrPolicy{Bsid: bsid},
			},
		}); err != nil {
			t.Fatalf("AddConnectivity prio=%d: %v", prio, err)
		}
	}

	if len(fake.delPolicy) != 0 {
		t.Fatalf("expected no DelSRv6Policy when BSID unchanged; got %+v", fake.delPolicy)
	}
}

// A second advertisement with a DIFFERENT NLRI key on the same endpoint must
// coexist as a candidate path — RFC 9256 candidate-path failover relies on
// this. This guards against the dedup logic over-applying.
func TestAddConnectivity_DifferentNLRIKeysCoexist(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	bsidA := mustBsid(t, "cafe::aaa")
	bsidB := mustBsid(t, "cafe::bbb")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	for _, tun := range []common.SRv6Tunnel{
		{Dst: dst, Color: 6, Distinguisher: 1, Priority: 100, Policy: &types.SrPolicy{Bsid: bsidA}},
		{Dst: dst, Color: 6, Distinguisher: 2, Priority: 50, Policy: &types.SrPolicy{Bsid: bsidB}},
	} {
		tun := tun
		if err := p.AddConnectivity(&common.NodeConnectivity{NextHop: dst, Custom: &tun}); err != nil {
			t.Fatalf("AddConnectivity: %v (tun=%+v)", err, tun)
		}
	}

	cache := p.nodePolices[dst.String()].SRv6Tunnel
	if len(cache) != 2 {
		t.Fatalf("expected 2 candidate paths to coexist; got %d (%+v)", len(cache), cache)
	}
}

// Idempotent delete: when DelSRv6Steering reports NO_SUCH_INNER_FIB (the L3
// key has already been removed from VPP's steering hash) and DelSRv6Policy
// reports UNSPECIFIED (the BSID has already been removed from VPP's policy
// hash), delSRPolicy must still complete its work. Failover re-steer must
// run; nodePolices must be pruned.
func TestDelSRPolicy_IdempotentWhenVPPAlreadyMissing(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::aaa")
	prefix := mustPrefix(t, "fd20::aaaa/128")
	surviverBsid := mustBsid(t, "cafe::bbb")

	fake := &fakeSRv6VPP{
		steering:       []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
		delSteeringErr: govppapi.NO_SUCH_INNER_FIB,
		delPolicyErr:   govppapi.UNSPECIFIED,
	}
	p := newTestProvider(fake)
	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: bsid}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 50, Policy: &types.SrPolicy{Bsid: surviverBsid}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	if len(fake.delSteering) != 1 || fake.delSteering[0].Bsid != bsid {
		t.Fatalf("expected DelSRv6Steering(bsid=%s); got %+v", bsid.String(), fake.delSteering)
	}
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != bsid {
		t.Fatalf("expected DelSRv6Policy(bsid=%s); got %+v", bsid.String(), fake.delPolicy)
	}
	// Failover still runs despite the VPP errors.
	if len(fake.addModPolicy) != 1 || fake.addModPolicy[0].Bsid != surviverBsid {
		t.Fatalf("expected AddModSRv6Policy(surviver=%s) for failover; got %+v", surviverBsid.String(), fake.addModPolicy)
	}
	if len(fake.addSteering) != 1 || fake.addSteering[0].Bsid != surviverBsid {
		t.Fatalf("expected AddSRv6Steering(surviver=%s) for failover; got %+v", surviverBsid.String(), fake.addSteering)
	}
}

func TestDelConnectivity_DispatcherRoutesByEventShape(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	// Empty cn (no Custom, no Dst.IP) must error so a malformed event is loud.
	if err := p.DelConnectivity(&common.NodeConnectivity{}); err == nil {
		t.Fatal("expected error for empty cn")
	}
}
