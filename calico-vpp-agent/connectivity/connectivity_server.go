// Copyright (C) 2021 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connectivity

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

type ConnectivityServer struct {
	log *logrus.Entry

	providers        map[string]ConnectivityProvider
	connectivityMap  map[string]common.NodeConnectivity
	policyServerIpam common.PolicyServerIpam
	Clientv3         calicov3cli.Interface
	nodeBGPSpec      *common.LocalNodeSpec
	vpp              *vpplink.VppLink

	felixConfig *felixConfig.Config
	nodeByAddr  map[string]common.LocalNodeSpec

	connectivityEventChan chan common.CalicoVppEvent

	networks map[uint32]watchers.NetworkDefinition
}

type change uint8

const (
	AddChange    change = 0
	DeleteChange change = 1
)

func (s *ConnectivityServer) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func (s *ConnectivityServer) SetFelixConfig(felixConfig *felixConfig.Config) {
	s.felixConfig = felixConfig
}

func NewConnectivityServer(vpp *vpplink.VppLink, policyServerIpam common.PolicyServerIpam,
	clientv3 calicov3cli.Interface, log *logrus.Entry) *ConnectivityServer {
	server := ConnectivityServer{
		log:                   log,
		vpp:                   vpp,
		policyServerIpam:      policyServerIpam,
		Clientv3:              clientv3,
		connectivityMap:       make(map[string]common.NodeConnectivity),
		connectivityEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
		nodeByAddr:            make(map[string]common.LocalNodeSpec),
		networks:              make(map[uint32]watchers.NetworkDefinition),
	}

	reg := common.RegisterHandler(server.connectivityEventChan, "connectivity server events")
	reg.ExpectEvents(
		common.NetAddedOrUpdated,
		common.NetDeleted,
		common.ConnectivityAdded,
		common.ConnectivityDeleted,
		common.PeerNodeStateChanged,
		common.FelixConfChanged,
		common.IpamConfChanged,
		common.SRv6PolicyAdded,
		common.SRv6PolicyDeleted,
		common.WireguardPublicKeyChanged,
	)

	nDataThreads := common.FetchNDataThreads(vpp, log)
	providerData := NewConnectivityProviderData(server.vpp, &server, log)

	server.providers = make(map[string]ConnectivityProvider)
	server.providers[FLAT] = NewFlatL3Provider(providerData)
	server.providers[IPIP] = NewIPIPProvider(providerData)
	server.providers[IPSEC] = NewIPsecProvider(providerData, nDataThreads)
	server.providers[VXLAN] = NewVXLanProvider(providerData)
	server.providers[WIREGUARD] = NewWireguardProvider(providerData)
	server.providers[SRv6] = NewSRv6Provider(providerData)

	return &server
}

func (s *ConnectivityServer) GetNodeByIp(addr net.IP) *common.LocalNodeSpec {
	ns, found := s.nodeByAddr[addr.String()]
	if !found {
		return nil
	}
	return &ns
}

func (s *ConnectivityServer) GetNodeIPs() (ip4 *net.IP, ip6 *net.IP) {
	ip4, ip6 = common.GetBGPSpecAddresses(s.nodeBGPSpec)
	return ip4, ip6
}

func (s *ConnectivityServer) GetNodeIPNet(isv6 bool) *net.IPNet {
	ip4, ip6 := s.nodeBGPSpec.IPv4Address, s.nodeBGPSpec.IPv6Address
	if isv6 {
		return ip6
	} else {
		return ip4
	}
}

func (s *ConnectivityServer) updateAllIPConnectivity() {
	for _, cn := range s.connectivityMap {
		err := s.UpdateIPConnectivity(&cn, false /* isWithdraw */)
		if err != nil {
			s.log.Errorf("Error while re-updating connectivity %s", err)
		}
	}
}

func (s *ConnectivityServer) ServeConnectivity(t *tomb.Tomb) error {
	/**
	 * There might be leftover state in VPP in case we restarted
	 * so first check what is present */
	for _, provider := range s.providers {
		provider.RescanState()
	}
	for {
		select {
		case <-t.Dying():
			s.log.Warn("Connectivity Server asked to stop")
			return nil
		case evt := <-s.connectivityEventChan:
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.NetAddedOrUpdated:
				new, ok := evt.New.(*watchers.NetworkDefinition)
				if !ok {
					s.log.Errorf("evt.New is not a *watchers.NetworkDefinition %v", evt.New)
				}
				s.networks[new.Vni] = *new
			case common.NetDeleted:
				old, ok := evt.Old.(*watchers.NetworkDefinition)
				if !ok {
					s.log.Errorf("evt.Old is not a *watchers.NetworkDefinition %v", evt.Old)
				}
				delete(s.networks, old.Vni)
			case common.ConnectivityAdded:
				new, ok := evt.New.(*common.NodeConnectivity)
				if !ok {
					s.log.Errorf("evt.New is not a *common.NodeConnectivity %v", evt.New)
				}
				err := s.UpdateIPConnectivity(new, false /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while adding connectivity %s", err)
				}
			case common.ConnectivityDeleted:
				old, ok := evt.Old.(*common.NodeConnectivity)
				if !ok {
					s.log.Errorf("evt.Old is not a *common.NodeConnectivity %v", evt.Old)
				}
				err := s.UpdateIPConnectivity(old, true /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while deleting connectivity %s", err)
				}
			case common.WireguardPublicKeyChanged:
				old, ok := evt.Old.(*common.NodeWireguardPublicKey)
				if !ok {
					s.log.Errorf("evt.Old is not a *common.NodeWireguardPublicKey %v", evt.Old)
				}
				new, ok := evt.New.(*common.NodeWireguardPublicKey)
				if !ok {
					s.log.Errorf("evt.New is not a *common.NodeWireguardPublicKey %v", evt.New)
				}
				s.providers[WIREGUARD].(*WireguardProvider).nodesToWGPublicKey[new.Name] = new.WireguardPublicKey
				change := common.GetStringChangeType(old.WireguardPublicKey, new.WireguardPublicKey)
				if change != common.ChangeSame {
					s.log.Infof("connectivity(upd) WireguardPublicKey Changed (%s) %s->%s", old.Name, old.WireguardPublicKey, new.WireguardPublicKey)
					s.updateAllIPConnectivity()
				}
			case common.PeerNodeStateChanged:
				old, ok := evt.Old.(*common.LocalNodeSpec)
				if !ok {
					s.log.Errorf("evt.Old is not a *common.LocalNodeSpec %v", evt.Old)
				}
				new, ok := evt.New.(*common.LocalNodeSpec)
				if !ok {
					s.log.Errorf("evt.New is not a *common.LocalNodeSpec %v", evt.New)
				}
				if old != nil {
					if old.IPv4Address != nil {
						delete(s.nodeByAddr, old.IPv4Address.IP.String())
					}
					if old.IPv6Address != nil {
						delete(s.nodeByAddr, old.IPv6Address.IP.String())
					}
				}
				if new != nil {
					if new.IPv4Address != nil {
						s.nodeByAddr[new.IPv4Address.IP.String()] = *new
					}
					if new.IPv6Address != nil {
						s.nodeByAddr[new.IPv6Address.IP.String()] = *new
					}
				}
			case common.FelixConfChanged:
				old, ok := evt.Old.(*felixConfig.Config)
				if !ok {
					s.log.Errorf("evt.Old is not a *felixConfig.Config %v", evt.Old)
				}
				new, ok := evt.New.(*felixConfig.Config)
				if !ok {
					s.log.Errorf("evt.Old is not a *felixConfig.Config %v", evt.New)
				}
				if new == nil || old == nil {
					/* First/last update, do nothing more */
					continue
				}
				s.felixConfig = new
				if old.WireguardEnabled != new.WireguardEnabled {
					s.log.Infof("connectivity(upd) WireguardEnabled Changed %t->%t", old.WireguardEnabled, new.WireguardEnabled)
					s.providers[WIREGUARD].EnableDisable(new.WireguardEnabled)
					s.updateAllIPConnectivity()
				} else if old.WireguardListeningPort != new.WireguardListeningPort {
					s.log.Warnf("connectivity(upd) WireguardListeningPort Changed [NOT IMPLEMENTED]")
				}
			case common.IpamConfChanged:
				s.log.Infof("connectivity(upd) ipamConf Changed")
				s.updateAllIPConnectivity()
			case common.SRv6PolicyAdded:
				new, ok := evt.New.(*common.NodeConnectivity)
				if !ok {
					s.log.Errorf("evt.New is not a *common.NodeConnectivity %v", evt.New)
				}
				err := s.UpdateSRv6Policy(new, false /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while adding SRv6 Policy %s", err)
				}
			case common.SRv6PolicyDeleted:
				old, ok := evt.Old.(*common.NodeConnectivity)
				if !ok {
					s.log.Errorf("evt.Old is not a *common.NodeConnectivity %v", evt.Old)
				}
				err := s.UpdateSRv6Policy(old, true /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while deleting SRv6 Policy %s", err)
				}
			}
		}
	}
}

func (s *ConnectivityServer) UpdateSRv6Policy(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
	s.log.Infof("updateSRv6Policy")
	providerType := SRv6
	if IsWithdraw {
		err = s.providers[providerType].DelConnectivity(cn)
	} else {
		err = s.providers[providerType].AddConnectivity(cn)
	}
	return err
}

func (s *ConnectivityServer) getProviderType(cn *common.NodeConnectivity) (string, error) {
	// use vxlan tunnel if secondary network, no need for ippool
	if cn.Vni != 0 {
		return VXLAN, nil
	}
	ipPool := s.policyServerIpam.GetPrefixIPPool(&cn.Dst)
	s.log.Debugf("IPPool for route %s: %+v", cn.String(), ipPool)
	if *config.GetCalicoVppFeatureGates().SRv6Enabled {
		return SRv6, nil
	}
	if ipPool == nil {
		return FLAT, nil
	}
	if ipPool.IpipMode == encap.Always {
		if s.providers[IPSEC].Enabled(cn) {
			return IPSEC, nil
		} else if s.providers[WIREGUARD].Enabled(cn) {
			return WIREGUARD, nil
		} else {
			return IPIP, nil
		}
	}
	nodeIpNet := s.GetNodeIPNet(vpplink.IsIP6(cn.Dst.IP))
	if ipPool.IpipMode == encap.CrossSubnet {
		if nodeIpNet == nil {
			return FLAT, fmt.Errorf("missing node IPnet")
		}
		if !nodeIpNet.Contains(cn.NextHop) {
			if s.providers[IPSEC].Enabled(cn) {
				return IPSEC, nil
			} else if s.providers[WIREGUARD].Enabled(cn) {
				return WIREGUARD, nil
			} else {
				return IPIP, nil
			}
		}
	}
	if ipPool.VxlanMode == encap.Always {
		if s.providers[WIREGUARD].Enabled(cn) {
			return WIREGUARD, nil
		}
		return VXLAN, nil
	}
	if ipPool.VxlanMode == encap.CrossSubnet {
		if nodeIpNet == nil {
			return FLAT, fmt.Errorf("missing node IPnet")
		}
		if !nodeIpNet.Contains(cn.NextHop) {
			if s.providers[WIREGUARD].Enabled(cn) {
				return WIREGUARD, nil
			}
			return VXLAN, nil
		}
	}
	return FLAT, nil
}

func (s *ConnectivityServer) UpdateIPConnectivity(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
	var providerType string
	if IsWithdraw {
		oldCn, found := s.connectivityMap[cn.String()]
		if !found {
			providerType, err = s.getProviderType(cn)
			if err != nil {
				return errors.Wrap(err, "getting provider failed")
			}
			s.log.Infof("connectivity(del) Didnt find provider in map, trying providerType=%s", providerType)
		} else {
			providerType = oldCn.ResolvedProvider
			delete(s.connectivityMap, oldCn.String())
			s.log.Infof("connectivity(del) path providerType=%s cn=%s", providerType, oldCn.String())
		}
		return s.providers[providerType].DelConnectivity(cn)
	} else {
		providerType, err = s.getProviderType(cn)
		if err != nil {
			return errors.Wrap(err, "getting provider failed")
		}
		oldCn, found := s.connectivityMap[cn.String()]
		if found {
			oldProviderType := oldCn.ResolvedProvider
			if oldProviderType != providerType {
				s.log.Infof("connectivity(upd) provider Change providerType=%s->%s cn=%s", oldProviderType, providerType, cn.String())
				err := s.providers[oldProviderType].DelConnectivity(cn)
				if err != nil {
					s.log.Errorf("Error del connectivity when changing provider %s->%s : %s", oldProviderType, providerType, err)
				}
				cn.ResolvedProvider = providerType
				s.connectivityMap[cn.String()] = *cn
				return s.providers[providerType].AddConnectivity(cn)
			} else {
				s.log.Infof("connectivity(same) path providerType=%s cn=%s", providerType, cn.String())
				return s.providers[providerType].AddConnectivity(cn)
			}
		} else {
			s.log.Infof("connectivity(add) path providerType=%s cn=%s", providerType, cn.String())
			cn.ResolvedProvider = providerType
			s.connectivityMap[cn.String()] = *cn
			return s.providers[providerType].AddConnectivity(cn)
		}
	}
}

// ForceRescanState forces to rescan VPP state (ConnectivityProvider.RescanState()) for initialized
// ConnectivityProvider of given type.
// The usage is mainly for testing purposes.
func (s *ConnectivityServer) ForceRescanState(providerType string) (err error) {
	provider, found := s.providers[providerType]
	if !found {
		return fmt.Errorf("can't find connectivity provider of type %s", providerType)
	}
	provider.RescanState()
	return nil
}

// ForceProviderEnableDisable force to enable/disable specific connectivity provider.
// The usage is mainly for testing purposes.
func (s *ConnectivityServer) ForceProviderEnableDisable(providerType string, enable bool) (err error) {
	provider, found := s.providers[providerType]
	if !found {
		return fmt.Errorf("can't find connectivity provider of type %s", providerType)
	}
	provider.EnableDisable(enable)
	return nil
}

// TODO get rid (if possible) of all this "Force" methods by refactor the test code
//  (run the ConnectivityServer.ServeConnectivity(...) function and send into it events with common.SendEvent(...))

// ForceNodeAddition will add other node information as provided by calico configuration
// The usage is mainly for testing purposes.
func (s *ConnectivityServer) ForceNodeAddition(newNode common.LocalNodeSpec, newNodeIP net.IP) {
	s.nodeByAddr[newNodeIP.String()] = newNode
}

// ForceWGPublicKeyAddition will add other node information as provided by calico configuration
// The usage is mainly for testing purposes.
func (s *ConnectivityServer) ForceWGPublicKeyAddition(newNode string, wgPublicKey string) {
	s.providers[WIREGUARD].(*WireguardProvider).nodesToWGPublicKey[newNode] = wgPublicKey
}
