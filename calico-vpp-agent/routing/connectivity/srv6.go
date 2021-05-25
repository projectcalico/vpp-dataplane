package connectivity

import (
	"context"
	"net"

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
	// TODO
	srv6Policies  map[string]*types.SrPolicy
	srv6Localsids map[string]*types.SrLocalsid
	srv6Steers    []*types.SrSteer
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*types.SrPolicy), make(map[string]*types.SrLocalsid), make([]*types.SrSteer, 0)}
	p.log.Printf("SRv6Provider NewSRv6Provider")

	return p
}

func (p *SRv6Provider) OnVppRestart() {
	p.srv6Policies = make(map[string]*types.SrPolicy)
	p.srv6Localsids = make(map[string]*types.SrLocalsid)
	p.srv6Steers = make([]*types.SrSteer, 0)
}

func (p *SRv6Provider) Enabled() bool {
	return config.EnableSRv6
}

func (p *SRv6Provider) RescanState() {
	p.log.Infof("SRv6Provider RescanState")
	p.setEncapSource()

	p.srv6Policies = make(map[string]*types.SrPolicy)
	policies, err := p.vpp.ListSRv6Policies()
	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SrPolicies: %v", err)
	}

	for _, policy := range policies {
		p.log.Infof("Found existing SrPolicy: %s", policy.String())
		p.srv6Policies[policy.Bsid.String()] = policy
	}

	p.srv6Localsids = make(map[string]*types.SrLocalsid)
	localSids, err := p.vpp.ListSRv6Localsid()
	endDt4Exist := false
	endDt6Exist := false

	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SRv6Localsid: %v", err)
	}
	for _, localSid := range localSids {
		p.log.Infof("Found existing SRv6Localsid: %s", localSid.String())
		p.log.Infof("localSid.Behavior: %d", int(localSid.Behavior))
		if int(localSid.Behavior) == 9 && localSid.FibTable == 0 {
			endDt4Exist = true
		}
		if int(localSid.Behavior) == 8 && localSid.FibTable == 0 {
			endDt6Exist = true
		}
	}
	if endDt4Exist == false {
		_, err := p.setEndDT(4)
		if err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT4: %v", err)
		}
	}
	if endDt6Exist == false {
		_, err := p.setEndDT(6)
		if err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT6: %v", err)
		}
	}
}

func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())
	if cn.Dst.IP.To16() != nil {
		bsid, err := p.getSid("cafe::/122")
		if err != nil {
			p.log.Errorf("SRv6Provider Error AddConnectivity: %v", err)
			return errors.Wrapf(err, "SRv6Provider AddConnectivity")
		}
		var ipaddr ip_types.IP6Address
		copy(ipaddr[:], cn.NextHop.To16())
		sidList := types.Srv6SidList{
			NumSids: 1,
			Weight:  0,
			Sids:    [16]ip_types.IP6Address{ipaddr},
		}
		err = p.vpp.AddSRv6Policy(&types.SrPolicy{
			Bsid:     bsid,
			IsSpray:  false,
			IsEncap:  true,
			FibTable: 0,
			SidLists: []types.Srv6SidList{sidList},
		})
		if err != nil {
			p.log.Errorf("SRv6Provider Error AddConnectivity: %v", err)
			return errors.Wrapf(err, "SRv6Provider AddConnectivity")
		}
	}
	return err
}

func (p *SRv6Provider) DelConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider DelConnectivity %s", cn.String())

	return nil
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

func (p *SRv6Provider) setEndDT(typeDT int) (newLocalSid *types.SrLocalsid, err error) {
	p.log.Printf("SRv6Provider setLocalsid setEndDT%d", typeDT)
	// temporary solution: assuming the IP6 is like  fd00::xyz0
	nodeIP6 := p.server.GetNodeIP(true)
	nodeIP6String := nodeIP6.String()
	sz := len(nodeIP6String)
	newLocalSidAddrStr := nodeIP6String[:sz-1]
	var behavior uint8
	if typeDT == 4 {
		newLocalSidAddrStr += "1"
		behavior = 9
	} else if typeDT == 6 {
		newLocalSidAddrStr += "2"
		behavior = 8
	}
	newLocalSidAddr := net.ParseIP(newLocalSidAddrStr)
	p.log.Infof("SRv6Provider new LocalSid ip %s", newLocalSidAddr.String())
	newLocalSid = &types.SrLocalsid{
		Localsid: types.ToVppIP6Address(newLocalSidAddr),
		EndPsp:   false,
		FibTable: 0,
	}
	newLocalSid.SetBehavior(behavior)
	err = p.vpp.AddSRv6Localsid(newLocalSid)
	if err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSid")
		return nil, errors.Wrapf(err, "SRv6Provider Error adding LocalSid")
	}

	return newLocalSid, err
}

func (p *SRv6Provider) getSid(ipnet string) (newLocalSidAddr ip_types.IP6Address, err error) {
	pinco := []cnet.IPNet{cnet.MustParseNetwork(ipnet)}
	_, localSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:      1,
		IPv6Pools: pinco,
	})
	if err != nil || localSids == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newLocalSidAddr, errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}

	newLocalSidAddr = types.ToVppIP6Address(localSids[0].IP)

	return newLocalSidAddr, nil
}
