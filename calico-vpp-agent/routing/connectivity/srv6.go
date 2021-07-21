package connectivity

import (
	"context"
	"net"

	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type Srv6TunnelData struct {
	Dst       net.IP
	PrefixDst ip_types.Prefix
	Bsid      ip_types.IP6Address
	Sid       ip_types.IP6Address
}

type NodeToPrefixes struct {
	Node     net.IP
	Prefixes []ip_types.Prefix
}

type NodeToPolicies struct {
	Node       net.IP
	SRv6Policy []SRv6PolicySingleSid
}

type SRv6PolicySingleSid struct {
	Bsid     ip_types.IP6Address
	Sid      ip_types.IP6Address
	Behavior types.SrBehavior
}

type SRv6Provider struct {
	*ConnectivityProviderData
	//srv6Tunnels  map[string]*Srv6TunnelData
	nodePrefixes map[string]*NodeToPrefixes
	nodePolices  map[string]*NodeToPolicies
	advertised   bool
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*NodeToPrefixes), make(map[string]*NodeToPolicies), false}
	p.log.Infof("SRv6Provider NewSRv6Provider")

	return p
}

func (p *SRv6Provider) OnVppRestart() {
	p.log.Infof("SRv6Provider OnVppRestart")
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
	_, err = p.createLocalSidTunnels(localSids)
	if err != nil {
		p.log.Errorf("SRv6Provider Error creating SRv6Localsid: %v", err)
	}

}

func (p *SRv6Provider) CreateSRv6Tunnnel(tunnelData *Srv6TunnelData) (err error) {
	p.log.Infof("SRv6Provider CreateSRv6Tunnnel")
	policySidList := types.Srv6SidList{
		NumSids: 1,
		Weight:  0,
		Sids:    [16]ip_types.IP6Address{tunnelData.Sid},
	}
	// create SRv6 Policy for encap
	newSRv6Policy := &types.SrPolicy{
		Bsid:     tunnelData.Bsid,
		IsSpray:  false,
		IsEncap:  true,
		FibTable: 0,
		SidLists: []types.Srv6SidList{policySidList},
	}

	err = p.vpp.AddSRv6Policy(newSRv6Policy)
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel %s", err)
	}

	srSteer := &types.SrSteer{
		TrafficType: types.SR_STEER_IPV6,
		Prefix:      tunnelData.PrefixDst,
		Bsid:        tunnelData.Bsid,
	}

	err = p.vpp.AddSRv6Steering(srSteer)

	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel %s", err)

	}

	singleSid := newSRv6Policy.SidLists[0].Sids[0]
	_, sidDstIPNet, err := net.ParseCIDR(singleSid.String() + "/128")
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel %s", err)
	}

	err = p.vpp.RouteAdd(&types.Route{
		Dst:   sidDstIPNet,
		Paths: []types.RoutePath{{Gw: tunnelData.Dst.To16(), SwIfIndex: config.DataInterfaceSwIfIndex}},
	})
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel %s", err)
	}

	return err
}

func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())
	if p.advertised == false {
		p.AdvertiseSRv6Policy()
	}
	var nodeip string
	// only IPv6 destination
	if vpplink.IsIP6(cn.NextHop) && cn.Dst.IP != nil {
		p.log.Infof("SRv6Provider AddConnectivity - Prefix data %s", cn.String())
		nodeip = cn.NextHop.String()
		prefix, err := ip_types.ParsePrefix(cn.Dst.String())
		if err != nil {
			return errors.Wrapf(err, "SRv6Provider unable to parse prefix")
		}

		if p.nodePrefixes[nodeip] == nil {
			p.nodePrefixes[nodeip] = &NodeToPrefixes{
				Node:     cn.NextHop,
				Prefixes: []ip_types.Prefix{},
			}
		}
		p.nodePrefixes[nodeip].Prefixes = append(p.nodePrefixes[nodeip].Prefixes, prefix)
		p.log.Infof("SRv6Provider just stored prefix for node %s", nodeip)

		if p.nodePolices[nodeip] == nil {
			p.log.Infof("SRv6Provider no policies for %s", nodeip)
			return err
		}

	} else if cn.Custom != nil {
		p.log.Infof("SRv6Provider AddConnectivity - Policy data %s", cn.String())
		p.log.Infof("SRv6Provider AddConnectivity - Policy data2 %s", cn)
		policyData := cn.Custom.(*common.SRv6Tunnel)
		p.log.Infof("SRv6Provider AddConnectivity - Policy data3 %s", policyData.Bsid)
		nodeip = policyData.Dst.String()
		if p.nodePolices[policyData.Dst.String()] == nil {
			p.nodePolices[policyData.Dst.String()] = &NodeToPolicies{
				Node:       policyData.Dst,
				SRv6Policy: []SRv6PolicySingleSid{},
			}
		}

		policySingleSid := SRv6PolicySingleSid{
			Bsid:     types.ToVppIP6Address(policyData.Bsid),
			Sid:      types.ToVppIP6Address(policyData.Sid),
			Behavior: types.SrBehavior(policyData.Behavior),
		}

		p.nodePolices[policyData.Dst.String()].SRv6Policy = append(p.nodePolices[policyData.Dst.String()].SRv6Policy, policySingleSid)
		p.log.Infof("SRv6Provider just stored policy for node %s and bsid %s", nodeip, policySingleSid.Bsid.String())
		// types.SrBehaviorDT6
		if p.nodePrefixes[nodeip] == nil {
			p.log.Infof("SRv6Provider no prefixes for %s", nodeip)
			return err
		}

	}
	if p.nodePrefixes[nodeip] != nil {
		p.log.Infof("SRv6Provider check new tunnel for node %s", nodeip)
		for _, prefix := range p.nodePrefixes[nodeip].Prefixes {
			prefixIP6 := vpplink.IsIP6(prefix.Address.ToIP())
			if p.nodePolices[nodeip] != nil {
				p.log.Infof("SRv6Provider check2 new tunnel for node %s", nodeip)
				for _, policy := range p.nodePolices[nodeip].SRv6Policy {
					if (policy.Behavior == 18 && prefixIP6) || (policy.Behavior == types.SrBehaviorDT4 && !prefixIP6) {
						err = p.CreateSRv6Tunnnel(&Srv6TunnelData{
							Dst:       p.nodePrefixes[nodeip].Node,
							PrefixDst: prefix,
							Bsid:      policy.Bsid,
							Sid:       policy.Sid,
						})

						if err != nil {
							p.log.Error(err)
						}
					}
				}
			}

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

func (p *SRv6Provider) createLocalSidTunnels(currentLocalSids []*types.SrLocalsid) (localSids []*types.SrLocalsid, err error) {
	p.log.Printf("SRv6Provider createLocalSidTunnels")
	endDt4Exist := true // TODO set to false
	endDt6Exist := false
	for _, localSid := range currentLocalSids {
		p.log.Infof("Found existing SRv6Localsid: %s", localSid.String())
		// this condition is not working... currently the value of localSid.Behavior is equal to 0
		if localSid.Behavior == types.SrBehaviorDT6 && localSid.FibTable == 0 {
			endDt6Exist = true
		}

		err = p.vpp.DelSRv6Localsid(localSid)
		if err != nil {
			p.log.Errorf("SRv6Provider Error DelSRv6Localsid: %v", err)
		}

		if localSid.Behavior == types.SrBehaviorDT4 && localSid.FibTable == 0 {
			endDt4Exist = true
		}
	}
	if !endDt4Exist {
		localSidDT4, err := p.setEndDT(4)
		if err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT4: %v", err)
		}
		localSids = append(localSids, localSidDT4)

	}
	if !endDt6Exist {
		localSidDT6, err := p.setEndDT(6)
		if err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT6: %v", err)
			return nil, err
		}

		localSids = append(localSids, localSidDT6)
	}
	return localSids, err
}

func (p *SRv6Provider) AdvertiseSRv6Policy() (err error) {
	localSids, err := p.vpp.ListSRv6Localsid()

	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SRv6Localsid: %v", err)
	}
	for _, localsid := range localSids {
		bsid, err := p.getSidFromPool("cafe::/118")
		if err != nil {
			p.log.Errorf("SRv6Provider Error getSidFromPool: %v", err)
		} else {
			newPath, err := common.MakePathSRv6Tunnel(localsid.Localsid.ToIP(), bsid.ToIP(), p.server.GetNodeIP(true), 6, false)
			if err == nil {
				/*
					p.server.BGPServer.ListPeer(context.Background(), &bgpapi.ListPeerRequest{}, func(peerlo *bgpapi.Peer) {
						p.log.Printf("Ciao Provider BGPPEER %s", peerlo.String())
					})*/
				p.log.Printf("SRv6Provider AdvertiseSRv6Policy %s, %s, %s, %d, %v", localsid.Localsid.ToIP().String(), bsid.ToIP().String(), p.server.GetNodeIP(true).String(), 6, false)
				_, err := p.server.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
					TableType: bgpapi.TableType_GLOBAL,
					Path:      newPath,
				})
				if err != nil {
					p.log.Errorf("SRv6Provider Error bgpserver.AddPath: %v", err)
				}

				p.advertised = true
			}
		}
	}
	return err
}

// Add a new SRLocalSid with end.DT4 or end.DT6 behavior
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
	poolIPNet := []cnet.IPNet{cnet.MustParseNetwork(ipnet)}
	_, newSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:      1,
		IPv6Pools: poolIPNet,
	})
	if err != nil || newSids == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}

	newSidAddr = types.ToVppIP6Address(newSids[0].IP)

	return newSidAddr, nil
}

func (p *SRv6Provider) getNewLocalSidAddr(typeDT int) (newLocalSidAddr ip_types.IP6Address, err error) {
	// development only solution: assuming the IP6 is fd00::xyz0
	nodeIP6 := p.server.GetNodeIP(true)

	return p.inferLocalSidAddr(typeDT, nodeIP6)
}

func (p *SRv6Provider) inferLocalSidAddr(typeDT int, ip net.IP) (newLocalSidAddr ip_types.IP6Address, err error) {
	// development only solution: assuming the IP6 is fd00::xyz0
	ipString := ip.String()
	sz := len(ipString)
	newLocalSidAddrStr := ipString[:sz-1]
	if typeDT == 4 {
		newLocalSidAddrStr += "1"
	} else if typeDT == 6 {
		newLocalSidAddrStr += "2"
	}

	return types.ToVppIP6Address(net.ParseIP(newLocalSidAddrStr)), nil
}
