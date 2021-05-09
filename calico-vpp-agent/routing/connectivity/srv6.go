package connectivity

import (
	"context"

	"github.com/pkg/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type SRv6Provider struct {
	*ConnectivityProviderData
	srv6Policies map[string]*types.SrPolicy
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*types.SrPolicy)}
	p.log.Printf("SRv6Provider NewSRv6Provider")

	return p
}

func (p *SRv6Provider) setEncapSource() (err error) {
	p.log.Printf("SRv6Provider setEncapSource")
	nodeIP6 := p.server.GetNodeIP(true)
	err = p.vpp.SetEncapSource(nodeIP6)
	if err != nil {
		p.log.Errorf("SRv6Provider setEncapSource: %v", err)
		return errors.Wrapf(err, "SRv6Provider setEncapSource")
	}

	return err
}

func (p *SRv6Provider) setEndDT4() (err error) {
	p.log.Printf("SRv6Provider setLocalsid setEndDT4")
	pinco := []cnet.IPNet{cnet.MustParseNetwork("c5::/122")}
	_, localSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:      1,
		IPv6Pools: pinco,
	})

	if err != nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}
	if localSids != nil {
		newLocalSidAddr := types.ToVppIP6Address(localSids[0].IP)
		p.log.Infof("SRv6Provider new LocalSid ip %s", newLocalSidAddr.String())
		newLocalSid := &types.SrLocalsid{
			Localsid: newLocalSidAddr,
			EndPsp:   false,
			Behavior: 9,
			FibTable: 0,
		}
		err = p.vpp.AddSRv6Localsid(newLocalSid)
		if err != nil {
			p.log.Infof("SRv6Provider Error adding LocalSid")
			return errors.Wrapf(err, "SRv6Provider Error adding LocalSid")
		}
	}

	return err
}

func (p *SRv6Provider) setEndDT6() (err error) {
	p.log.Printf("SRv6Provider  setLocalsid setEndDT6")
	//_, localSidsIPNET, err := net.ParseCIDR("c5::/122")
	pinco := []cnet.IPNet{cnet.MustParseNetwork("c5::/122")}
	_, localSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:      1,
		IPv6Pools: pinco,
	})

	if err != nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}
	if localSids != nil {
		newLocalSidAddr := types.ToVppIP6Address(localSids[0].IP)
		p.log.Infof("SRv6Provider new LocalSid ip %s", newLocalSidAddr.String())
		newLocalSid := &types.SrLocalsid{
			Localsid: newLocalSidAddr,
			EndPsp:   false,
			Behavior: 8,
			FibTable: 0,
		}
		err = p.vpp.AddSRv6Localsid(newLocalSid)
		if err != nil {
			p.log.Infof("SRv6Provider Error adding LocalSid")
			return errors.Wrapf(err, "SRv6Provider Error adding LocalSid")
		}
	}

	return err
}

func (p *SRv6Provider) OnVppRestart() {
	p.srv6Policies = make(map[string]*types.SrPolicy)
}

func (p *SRv6Provider) Enabled() bool {
	return config.EnableSRv6
}

func (p *SRv6Provider) RescanState() {
	p.log.Infof("SRv6Provider RescanState")
	p.setEncapSource()
	//p.setEndDT4()
	//p.setEndDT6()
	p.srv6Policies = make(map[string]*types.SrPolicy)
	_, err := p.vpp.ListSRv6Policies()
	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SrPolicies: %v", err)
	}

	/*nodeIP6 := p.server.GetNodeIP(true)
	for _, policy := range policies {
		policyIP6 := policy.Bsid.ToIP()
		if nodeIP6.Equal(policyIP6) {
			p.log.Infof("Found existing SrPolicy: %s", policy)
			p.srv6Policies[policy.Bsid.String()] = policy
		}
	} */

}

func (p *SRv6Provider) errorCleanup(policy *types.SrPolicy) {
	err := p.vpp.DelSRv6Policy(policy)
	if err != nil {
		p.log.Errorf("Error deleting SrPolicy %s after error: %v", policy, err)
	}
}

func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Debugf("SRv6Provider Adding SrPolicy to VPP")
	listLocalSid, err := p.vpp.ListSRv6Localsid()
	var localSids *types.SrLocalsid
	if err != nil {
		p.log.Infof("SRv6Provider Error finding LocalSids")
		return errors.Wrapf(err, "SRv6Provider Error finding LocalSids")
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
		p.log.Infof("SRv6Provider Adding SrPolicy %s ", policy)
		err := p.vpp.AddSRv6Policy(policy)
		if err != nil {
			return errors.Wrapf(err, "Error adding SrPolicy ")
		}
		//TODO
		p.srv6Policies[cn.NextHop.String()] = policy
	}
	p.log.Infof("SRv6Provider policy ok")

	p.log.Debugf("SRv6Provider Adding SrPolicy route to %s via swIfIndex %d", cn.Dst.IP.String(), localSids.SwIfIndex)
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

func (p *SRv6Provider) DelConnectivity(cn *common.NodeConnectivity) error {
	_, found := p.srv6Policies[cn.NextHop.String()]
	if !found {
		p.log.Infof("SRv6Provider Del unknown %s", cn.NextHop.String())
		return errors.Errorf("SRv6Provider Deleting unknown SrPolicy %s", cn.NextHop.String())
	}
	err := p.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			Gw: nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "SRv6Provider Error deleting policy route")
	}
	// TODO remove route
	return nil
}
