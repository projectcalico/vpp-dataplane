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
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	felixConfig "github.com/projectcalico/calico/felix/config"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

type ConnectivityServer struct {
	log *logrus.Entry

	providers       map[string]ConnectivityProvider
	connectivityMap map[string]common.NodeConnectivity
	ipam            watchers.IpamCache
	Clientv3        calicov3cli.Interface
	nodeBGPSpec     *oldv3.NodeBGPSpec
	vpp             *vpplink.VppLink

	felixConfig *felixConfig.Config
	nodeByAddr  map[string]oldv3.Node

	connectivityEventChan chan common.CalicoVppEvent

	networks map[uint32]watchers.NetworkDefinition
}

type change uint8

const (
	AddChange    change = 0
	DeleteChange change = 1
)

func (s *ConnectivityServer) SetOurBGPSpec(nodeBGPSpec *oldv3.NodeBGPSpec) {
	s.nodeBGPSpec = nodeBGPSpec
}

func (s *ConnectivityServer) SetFelixConfig(felixConfig *felixConfig.Config) {
	s.felixConfig = felixConfig
}

func NewConnectivityServer(vpp *vpplink.VppLink, ipam watchers.IpamCache,
	clientv3 calicov3cli.Interface, log *logrus.Entry) *ConnectivityServer {
	server := ConnectivityServer{
		log:                   log,
		vpp:                   vpp,
		ipam:                  ipam,
		Clientv3:              clientv3,
		connectivityMap:       make(map[string]common.NodeConnectivity),
		connectivityEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
		nodeByAddr:            make(map[string]oldv3.Node),
		networks:              make(map[uint32]watchers.NetworkDefinition),
	}

	reg := common.RegisterHandler(server.connectivityEventChan, "connectivity server events")
	reg.ExpectEvents(
		common.NetAdded,
		common.NetDeleted,
		common.ConnectivityAdded,
		common.ConnectivityDeleted,
		common.PeerNodeStateChanged,
		common.FelixConfChanged,
		common.IpamConfChanged,
		common.SRv6PolicyAdded,
		common.SRv6PolicyDeleted,
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

func isCrossSubnet(gw net.IP, subnet net.IPNet) bool {
	return !subnet.Contains(gw)
}

func (s *ConnectivityServer) GetNodeByIp(addr net.IP) *oldv3.Node {
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
	ip4, ip6 := common.GetBGPSpecIPNet(s.nodeBGPSpec)
	if isv6 {
		return ip6
	} else {
		return ip4
	}
}

func (s *ConnectivityServer) updateAllIPConnectivity() {
	for _, cn := range s.connectivityMap {
		err := s.updateIPConnectivity(&cn, false /* isWithdraw */)
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
			s.log.Infof("Connectivity Server asked to stop")
			return nil
		case evt := <-s.connectivityEventChan:
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.NetAdded:
				new := evt.New.(*watchers.NetworkDefinition)
				s.networks[new.Vni] = *new
			case common.NetDeleted:
				old := evt.Old.(*watchers.NetworkDefinition)
				delete(s.networks, old.Vni)
			case common.NetUpdated:
				old := evt.Old.(*watchers.NetworkDefinition)
				new := evt.New.(*watchers.NetworkDefinition)
				delete(s.networks, old.Vni)
				s.networks[new.Vni] = *new
			case common.ConnectivityAdded:
				new := evt.New.(*common.NodeConnectivity)
				err := s.updateIPConnectivity(new, false /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while adding connectivity %s", err)
				}
			case common.ConnectivityDeleted:
				old := evt.Old.(*common.NodeConnectivity)
				err := s.updateIPConnectivity(old, true /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while deleting connectivity %s", err)
				}
			case common.PeerNodeStateChanged:
				old, _ := evt.Old.(*oldv3.Node)
				new, _ := evt.New.(*oldv3.Node)
				if old != nil {
					oldV4IP, oldV6IP := common.GetNodeSpecAddresses(old)
					if oldV4IP != "" {
						delete(s.nodeByAddr, oldV4IP)
					}
					if oldV6IP != "" {
						delete(s.nodeByAddr, oldV6IP)
					}
				}
				if new != nil {
					newV4IP, newV6IP := common.GetNodeSpecAddresses(new)
					if newV4IP != "" {
						s.nodeByAddr[newV4IP] = *new
					}
					if newV6IP != "" {
						s.nodeByAddr[newV6IP] = *new
					}
				}
				if old != nil && new != nil {
					change := common.GetStringChangeType(old.Status.WireguardPublicKey, new.Status.WireguardPublicKey)
					if change != common.ChangeSame {
						s.log.Infof("connectivity(upd) WireguardPublicKey Changed (%s) %s->%s", old.Name, old.Status.WireguardPublicKey, new.Status.WireguardPublicKey)
						s.updateAllIPConnectivity()
					}
				}
			case common.FelixConfChanged:
				old, _ := evt.Old.(*felixConfig.Config)
				new, _ := evt.New.(*felixConfig.Config)
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
				old, _ := evt.Old.(*calicov3.IPPool)
				new, _ := evt.New.(*calicov3.IPPool)
				if old == nil || new == nil {
					/* First/last update, do nothing*/
					continue
				}
				if new.Spec.VXLANMode != old.Spec.VXLANMode ||
					new.Spec.IPIPMode != old.Spec.IPIPMode {
					s.log.Infof("connectivity(upd) VXLAN/IPIPMode Changed")
					s.updateAllIPConnectivity()
				}
			case common.SRv6PolicyAdded:
				new := evt.New.(*common.NodeConnectivity)
				err := s.updateSRv6Policy(new, false /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while adding SRv6 Policy %s", err)
				}
			case common.SRv6PolicyDeleted:
				old := evt.Old.(*common.NodeConnectivity)
				err := s.updateSRv6Policy(old, true /* isWithdraw */)
				if err != nil {
					s.log.Errorf("Error while deleting SRv6 Policy %s", err)
				}
			}
		}
	}
}

func (s *ConnectivityServer) updateSRv6Policy(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
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
	ipPool := s.ipam.GetPrefixIPPool(&cn.Dst)
	if config.EnableSRv6 {
		return SRv6, nil
	}
	if ipPool == nil {
		return FLAT, nil
	}
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeAlways {
		if s.providers[IPSEC].Enabled(cn) {
			return IPSEC, nil
		} else if s.providers[WIREGUARD].Enabled(cn) {
			return WIREGUARD, nil
		} else {
			return IPIP, nil
		}
	}
	ipNet := s.GetNodeIPNet(vpplink.IsIP6(cn.Dst.IP))
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeCrossSubnet {
		if ipNet == nil {
			return FLAT, fmt.Errorf("missing node IPnet")
		}
		if !isCrossSubnet(cn.NextHop, *ipNet) {
			if s.providers[IPSEC].Enabled(cn) {
				return IPSEC, nil
			} else if s.providers[WIREGUARD].Enabled(cn) {
				return WIREGUARD, nil
			} else {
				return IPIP, nil
			}
		}
	}
	if ipPool.Spec.VXLANMode == calicov3.VXLANModeAlways {
		return VXLAN, nil
	}
	if ipPool.Spec.VXLANMode == calicov3.VXLANModeCrossSubnet {
		if ipNet == nil {
			return FLAT, fmt.Errorf("missing node IPnet")
		}
		if !isCrossSubnet(cn.NextHop, *ipNet) {
			return VXLAN, nil
		}
	}
	return FLAT, nil
}

func (s *ConnectivityServer) updateIPConnectivity(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
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
