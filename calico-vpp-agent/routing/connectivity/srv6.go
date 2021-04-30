package connectivity

import (
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type SRv6Provider struct {
	*ConnectivityProviderData
	srv6Policies map[string]*types.SrPolicy
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*types.SrPolicy)}
	p.log.Printf("NewSRv6Provider")
	return p
}

func (p *SRv6Provider) OnVppRestart() {
	p.srv6Policies = make(map[string]*types.SrPolicy)
}

func (p *SRv6Provider) Enabled() bool {
	// TODO check config
	return true
}

func (p *SRv6Provider) RescanState() {
	p.log.Infof("Rescanning existing SrPolicies")
	p.srv6Policies = make(map[string]*types.SrPolicy)
	policies, err := p.vpp.ListSRv6Policies()
	if err != nil {
		p.log.Errorf("Error listing SrPolicies: %v", err)
	}

	nodeIP6 := p.server.GetNodeIP(true)
	for _, policy := range policies {
		policyIP6 := policy.Bsid.ToIP()
		if nodeIP6.Equal(policyIP6) {
			p.log.Infof("Found existing SrPolicy: %s", policy)
			p.srv6Policies[policy.Bsid.String()] = policy
		}
	}

}

func (p *SRv6Provider) errorCleanup(policy *types.SrPolicy) {
	err := p.vpp.DelSRv6Policy(policy)
	if err != nil {
		p.log.Errorf("Error deleting SrPolicy %s after error: %v", policy, err)
	}
}

func (p *SRv6Provider) AddConnectivity(cn *NodeConnectivity) error {
	p.log.Debugf("SRv6: Adding SrPolicy to VPP")
	listLocalSid, err := p.vpp.ListSRv6Localsid()
	var localSids *types.SrLocalsid
	if err != nil {
		p.log.Infof("SRv6: Error finding LocalSids")
		return errors.Wrapf(err, "SRv6: Error finding LocalSids")
	}
	for _, localSidss := range listLocalSid {
		localSids = localSidss
	}
	// TODO should manage it in a different way
	_, found := p.srv6Policies[cn.NextHop.String()]

	if !found {
		// TODO should use localsid
		nodeIP6 := p.server.GetNodeIP(true)
		//sids := make([]ip_types.IP6Address, 16)
		//sids[0] = cn.Dst.IP
		var ipaddr ip_types.IP6Address
		copy(ipaddr[:], cn.NextHop.To16())
		policy := &types.SrPolicy{
			Bsid:     types.ToVppIP6Address(nodeIP6),
			IsSpray:  false,
			IsEncap:  true,
			FibTable: 1,
			SidLists: types.Srv6SidList{
				NumSids: 1,
				Weight:  0,
				SlIndex: 0,
				Sids:    [16]ip_types.IP6Address{ipaddr},
			},
		}
		p.log.Infof("SRv6: Adding SrPolicy %s ", policy)
		err := p.vpp.AddSRv6Policy(policy)
		if err != nil {
			return errors.Wrapf(err, "Error adding SrPolicy ")
		}
		//TODO
		p.srv6Policies[cn.NextHop.String()] = policy
	}
	p.log.Infof("SRv6: policy ok")

	p.log.Debugf("SRv6: Adding SrPolicy route to %s via swIfIndex %d", cn.Dst.IP.String(), localSids.SwIfIndex)
	err_add_route := p.vpp.RouteAdd(&types.Route{
		Dst:   &cn.Dst,
		Paths: []types.RoutePath{{SwIfIndex: uint32(localSids.SwIfIndex), Gw: nil}},
		Table: 0,
	})
	if err_add_route != nil {
		return errors.Wrapf(err_add_route, "Error Adding route to SrPolicy")
	}
	return nil
}

func (p *SRv6Provider) DelConnectivity(cn *NodeConnectivity) error {
	_, found := p.srv6Policies[cn.NextHop.String()]
	if !found {
		p.log.Infof("SRv6: Del unknown %s", cn.NextHop.String())
		return errors.Errorf("Deleting unknown SrPolicy %s", cn.NextHop.String())
	}
	err := p.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			Gw: nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting policy route")
	}
	// TODO remove route
	return nil
}
