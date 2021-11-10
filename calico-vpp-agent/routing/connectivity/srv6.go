package connectivity

import (
	"context"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type NodeToPrefixes struct {
	Node     net.IP
	Prefixes []ip_types.Prefix
}

type NodeToPolicies struct {
	Node       net.IP
	SRv6Tunnel []common.SRv6Tunnel
}

type SRv6Provider struct {
	*ConnectivityProviderData

	nodePrefixes   map[string]*NodeToPrefixes
	nodePolices    map[string]*NodeToPolicies
	policyIPPool   net.IPNet
	localSidIPPool net.IPNet
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*NodeToPrefixes), make(map[string]*NodeToPolicies), net.IPNet{}, net.IPNet{}}
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

func (p *SRv6Provider) CreateSRv6Tunnnel(dst net.IP, prefixDst ip_types.Prefix, policyTunnel *types.SrPolicy) (err error) {
	p.log.Infof("SRv6Provider CreateSRv6Tunnnel")

	err = p.vpp.AddModSRv6Policy(policyTunnel)
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel AddSRv6Policy %s", err)

	}
	srSteer := &types.SrSteer{
		TrafficType: types.SR_STEER_IPV4,
		Prefix:      prefixDst,
		Bsid:        policyTunnel.Bsid,
	}

	// Change the traffic type if is an IPv6 addr
	if vpplink.IsIP6(srSteer.Prefix.Address.ToIP()) {
		srSteer.TrafficType = types.SR_STEER_IPV6
	}
	err = p.vpp.AddSRv6Steering(srSteer)

	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel AddSRv6Steering %s", err)

	}

	// TODO: temporary solution
	singleSid := policyTunnel.SidLists[0].Sids[0]
	_, sidDstIPNet, err := net.ParseCIDR(singleSid.String() + "/128")
	if err != nil {
		p.log.Errorf("SRv6Provider CreateSRv6Tunnnel ParseCIDR subnet %s", err)
	}

	err = p.vpp.RouteAdd(&types.Route{
		Dst:   sidDstIPNet,
		Paths: []types.RoutePath{{Gw: dst.To16(), SwIfIndex: config.DataInterfaceSwIfIndex}},
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
				SRv6Tunnel: []common.SRv6Tunnel{},
			}
		}

		p.log.Debugf("SRv6Provider new policy %s with behavior %d on node %s ", policyData.Bsid.String(), policyData.Behavior, nodeip)
		p.nodePolices[policyData.Dst.String()].SRv6Tunnel = append(p.nodePolices[policyData.Dst.String()].SRv6Tunnel, *policyData)

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
				for _, tunnel := range p.nodePolices[nodeip].SRv6Tunnel {
					p.log.Debugf("SRv6Provider available tunnel for node %s, prefixes %d", nodeip, len(p.nodePrefixes[nodeip].Prefixes))
					// this check
					if (types.FromGoBGPSrBehavior(tunnel.Behavior) == types.SrBehaviorDT6 && prefixIP6) || (types.FromGoBGPSrBehavior(tunnel.Behavior) == types.SrBehaviorDT4 && !prefixIP6) {
						if err := p.CreateSRv6Tunnnel(p.nodePrefixes[nodeip].Node, prefix, tunnel.Policy); err != nil {
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
	if err = p.vpp.SetEncapSource(nodeIP6); err != nil {
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
	p.log.Printf("SRv6Provider setLocalsid setEndDT%d", typeDT)

	var behavior types.SrBehavior
	switch typeDT {
	case 4:
		behavior = types.SrBehaviorDT4
	case 6:
		behavior = types.SrBehaviorDT6
	}

	poolLocalSIDName := "sr-localsids-pool-" + config.NodeName
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
		Num6:      1,
		IPv6Pools: poolIPNet,
	})
	if err != nil || newSids == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error getSidFromPool")
	}

	newSidAddr = types.ToVppIP6Address(newSids.IPs[0].IP)

	return newSidAddr, nil
}
