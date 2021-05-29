package connectivity

import (
	"context"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type SRv6Provider struct {
	*ConnectivityProviderData
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d}
	p.log.Printf("SRv6Provider NewSRv6Provider")

	return p
}

func (p *SRv6Provider) OnVppRestart() {

}

func (p *SRv6Provider) Enabled() bool {
	return config.EnableSRv6
}

func (p *SRv6Provider) RescanState() {
	p.log.Infof("SRv6Provider RescanState")
	p.setEncapSource()

	localSids, err := p.vpp.ListSRv6Localsid()
	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SRv6Localsid: %v", err)
	}
	//endDt4Exist := false
	endDt6Exist := false
	for _, localSid := range localSids {
		p.log.Infof("Found existing SRv6Localsid: %s", localSid.String())
		p.log.Infof("localSid.Behavior: %s", uint8(localSid.Behavior))
		p.log.Infof("localSid.Behavior is DT4 %v", localSid.Behavior == types.SrBehaviorDT4)
		p.log.Infof("localSid.Behavior is DT6 %v", localSid.Behavior == types.SrBehaviorDT6)
		// if localSid.Behavior == types.SrBehaviorDT4 && localSid.FibTable == 0 {
		// 	endDt4Exist = true
		// }
		if localSid.Behavior == types.SrBehaviorDT6 && localSid.FibTable == 0 {
			endDt6Exist = true
		}
	}
	/* 	if endDt4Exist == false {
		_, err := p.setEndDT(4)
		if err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT4: %v", err)
		}
	} */
	if !endDt6Exist {
		_, err := p.setEndDT(6)
		if err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT6: %v", err)
		}
	}
}

func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())
	if vpplink.IsIP6(cn.NextHop) {
		bsid, err := p.getSidFromPool("cafe::/122")
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

	var behavior types.SrBehavior
	switch typeDT {
	case 4:
		behavior = types.SrBehaviorDT4
	case 6:
		behavior = types.SrBehaviorDT6
	}
	newLocalSidAddr, err := p.getNewLocalSidAddr(typeDT)
	if err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSidAddr")
		return nil, errors.Wrapf(err, "SRv6Provider Error adding LocalSidAddr")
	}
	p.log.Infof("SRv6Provider new LocalSid ip %s", newLocalSidAddr.String())
	newLocalSid = &types.SrLocalsid{
		Localsid: newLocalSidAddr,
		EndPsp:   false,
		FibTable: 0,
		Behavior: behavior,
	}
	err = p.vpp.AddSRv6Localsid(newLocalSid)
	if err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSid")
		return nil, errors.Wrapf(err, "SRv6Provider Error adding LocalSid")
	}

	return newLocalSid, err
}

func (p *SRv6Provider) getSidFromPool(ipnet string) (newSidAddr ip_types.IP6Address, err error) {
	pinco := []cnet.IPNet{cnet.MustParseNetwork(ipnet)}
	_, newSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:      1,
		IPv6Pools: pinco,
	})
	if err != nil || newSids == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}

	newSidAddr = types.ToVppIP6Address(newSids[0].IP)

	return newSidAddr, nil
}

func (p *SRv6Provider) getNewLocalSidAddr(typeDT int) (newLocalSidAddr ip_types.IP6Address, err error) {
	// for test only solution: assuming the IP6 is fd00::xyz0
	nodeIP6 := p.server.GetNodeIP(true)
	nodeIP6String := nodeIP6.String()
	sz := len(nodeIP6String)
	newLocalSidAddrStr := nodeIP6String[:sz-1]

	if typeDT == 4 {
		newLocalSidAddrStr += "1"

	} else if typeDT == 6 {
		newLocalSidAddrStr += "2"
	}

	return types.ToVppIP6Address(net.ParseIP(newLocalSidAddrStr)), nil
}
