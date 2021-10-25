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
	nodePrefixes   map[string]*NodeToPrefixes
	nodePolices    map[string]*NodeToPolicies
	localSidIPPool net.IPNet
	policyIPPool   net.IPNet
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*NodeToPrefixes), make(map[string]*NodeToPolicies), net.IPNet{}, net.IPNet{}, false}
	if p.Enabled() {
		p.localSidIPPool = cnet.MustParseNetwork(config.SRv6localSidIPPool).IPNet
		p.policyIPPool = cnet.MustParseNetwork(config.SRv6policyIPPool).IPNet
	}

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
	if !p.Enabled() {
		return
	}
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
	err = p.vpp.AddModSRv6Policy(newSRv6Policy)
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel AddSRv6Policy %s", err)

	}
	srSteer := &types.SrSteer{
		TrafficType: types.SR_STEER_IPV4,
		Prefix:      tunnelData.PrefixDst,
		Bsid:        tunnelData.Bsid,
	}

	// Change the traffic type if is an IPv6 addr
	if vpplink.IsIP6(srSteer.Prefix.Address.ToIP()) {
		srSteer.TrafficType = types.SR_STEER_IPV6
	}
	err = p.vpp.AddSRv6Steering(srSteer)

	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel AddSRv6Steering %s", err)

	}

	singleSid := newSRv6Policy.SidLists[0].Sids[0]
	_, sidDstIPNet, err := net.ParseCIDR(singleSid.String() + "/128")
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel ParseCIDR subnet %s", err)
	}

	err = p.vpp.RouteAdd(&types.Route{
		Dst:   sidDstIPNet,
		Paths: []types.RoutePath{{Gw: tunnelData.Dst.To16(), SwIfIndex: config.DataInterfaceSwIfIndex}},
	})
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel RouteAdd %s", err)
	}

	return err
}

func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())

	var nodeip string
	// only IPv6 destination
	if vpplink.IsIP6(cn.NextHop) && cn.Dst.IP != nil {
		if p.localSidIPPool.Contains(cn.Dst.IP) || p.policyIPPool.Contains(cn.Dst.IP) {
			p.log.Infof("SRv6Provider AddConnectivity no valid prefix %s", cn.Dst.String())
			return err
		}
		nodeip = cn.NextHop.String()
		prefix, err := ip_types.ParsePrefix(cn.Dst.String())
		p.log.Debugf("SRv6Provider AddConnectivity prefix %s for node %s", prefix.String(), nodeip)

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

		if p.nodePolices[nodeip] == nil {
			p.log.Infof("SRv6Provider no policies for %s", nodeip)
			return err
		}

	} else if cn.Custom != nil {

		policyData := cn.Custom.(*common.SRv6Tunnel)
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
			Behavior: types.FromGoBGPSrBehavior(policyData.Behavior),
		}
		p.log.Debugf("SRv6Provider new policy %s with behavior %d on node %s ", policyData.Bsid.String(), policyData.Behavior, nodeip)
		p.nodePolices[policyData.Dst.String()].SRv6Policy = append(p.nodePolices[policyData.Dst.String()].SRv6Policy, policySingleSid)

		if p.nodePrefixes[nodeip] == nil {
			p.log.Debugf("SRv6Provider no prefixes for %s", nodeip)
			return err
		}

	}
	if p.nodePrefixes[nodeip] != nil {
		p.log.Debugf("SRv6Provider check new tunnel for node %s, prefixes %d", nodeip, len(p.nodePrefixes[nodeip].Prefixes))

		for _, prefix := range p.nodePrefixes[nodeip].Prefixes {
			prefixIP6 := vpplink.IsIP6(prefix.Address.ToIP())
			if p.nodePolices[nodeip] != nil {
				for _, policy := range p.nodePolices[nodeip].SRv6Policy {
					p.log.Debugf("SRv6Provider new tunnel for node %s and prefix %s with policy %s with behavior %d ", nodeip, prefix.Address.String(), policy.Bsid.String(), policy.Behavior)
					if (policy.Behavior == types.SrBehaviorDT6 && prefixIP6) || (policy.Behavior == types.SrBehaviorDT4 && !prefixIP6) {
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
	p.log.Debugf("SRv6Provider setEncapSource with IP6 %s", nodeIP6.String())
	return err
}

func (p *SRv6Provider) createLocalSidTunnels(currentLocalSids []*types.SrLocalsid) (localSids []*types.SrLocalsid, err error) {
	p.log.Printf("SRv6Provider createLocalSidTunnels")
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
	if config.SRv6localSidIPPool == "" {
		return nil, errors.New("localSidIPPool is not defined")
	}
	newLocalSidAddr, err := p.getSidFromPool(config.SRv6localSidIPPool)

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

	newSidAddr = types.ToVppIP6Address(newSids.IPs[0].IP)

	return newSidAddr, nil
}
