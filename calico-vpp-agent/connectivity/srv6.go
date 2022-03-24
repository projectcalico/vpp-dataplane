package connectivity

import (
	"context"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

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

// SRv6Provider is node connectivity provider that uses segment routing over IPv6 (SRv6) to connect the nodes
// For more info about SRv6, see https://datatracker.ietf.org/doc/html/rfc8986.
type SRv6Provider struct {
	*ConnectivityProviderData

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
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{d, make(map[string]*NodeToPrefixes), make(map[string]*NodeToPolicies), net.IPNet{}, net.IPNet{}}
	if config.EnableSRv6 {
		p.localSidIPPool = cnet.MustParseNetwork(config.SRv6localSidIPPool).IPNet
		p.policyIPPool = cnet.MustParseNetwork(config.SRv6policyIPPool).IPNet
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
	return config.EnableSRv6
}

// RescanState recreates(if missing in VPP) the static parts of the SRv6 tunneling on this node:
// 1. missing locasids (possible SRv6 tunnel endpoints) if they are not existing.
// 2. source encapsulation setting (pointing to IP of this node)
func (p *SRv6Provider) RescanState() {
	p.log.Infof("SRv6Provider RescanState")

	if !config.EnableSRv6 {
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
func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())

	var nodeip string
	// processing normal NodeConnectivity data only IPv6 destination
	if vpplink.IsIP6(cn.NextHop) && !p.isSRv6TunnelInfoFromBGP(cn) {
		// destination IP can't be from policy IPPool, because this IPPool is reserved for policy BSIDs
		if p.policyIPPool.Contains(cn.Dst.IP) {
			p.log.Infof("SRv6Provider AddConnectivity no valid prefix %s", cn.Dst.String())
			return err
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
				Paths: []types.RoutePath{{Gw: cn.NextHop.To16(), SwIfIndex: config.DataInterfaceSwIfIndex}},
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
			return err
		}

	} else if p.isSRv6TunnelInfoFromBGP(cn) && cn.Custom != nil { // getting SRv6 tunnel data from BGP

		// storing info in nodePolices
		policyData := cn.Custom.(*common.SRv6Tunnel)
		nodeip = policyData.Dst.String()
		if p.nodePolices[policyData.Dst.String()] == nil {
			p.nodePolices[policyData.Dst.String()] = &NodeToPolicies{
				Node:       policyData.Dst,
				SRv6Tunnel: []common.SRv6Tunnel{},
			}
		}

		p.log.Debugf("SRv6Provider new policy %s with behavior %d on node %s and priority %d", policyData.Bsid.String(), policyData.Behavior, nodeip, policyData.Priority)
		p.nodePolices[policyData.Dst.String()].SRv6Tunnel = append(p.nodePolices[policyData.Dst.String()].SRv6Tunnel, *policyData)

		// stopping processing until we have also needed normal common.NodeConnectivity data
		if p.nodePrefixes[nodeip] == nil {
			p.log.Debugf("SRv6Provider no prefixes for %s", nodeip)
			return err
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

	return err
}

func (p *SRv6Provider) DelConnectivity(cn *common.NodeConnectivity) (err error) {
	p.log.Infof("SRv6Provider DelConnectivity %s", cn.String())
	// FIXME SRv6 node connectivity removal not supported
	return nil
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
		for _, tunnel := range p.nodePolices[nodeip].SRv6Tunnel {
			if types.FromGoBGPSrBehavior(tunnel.Behavior) == behavior && tunnel.Priority >= priority {
				priority = tunnel.Priority
				policy = tunnel.Policy
			}
		}
	}
	return policy, err
}

func (p *SRv6Provider) setEncapSource() (err error) {
	p.log.Infof("SRv6Provider setEncapSource")
	_, nodeIP6 := p.GetNodeIPs()
	if nodeIP6 == nil {
		return fmt.Errorf("No ip6 found for node")
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
