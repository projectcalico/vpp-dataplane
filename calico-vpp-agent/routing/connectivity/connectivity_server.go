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
	"net"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/watchers"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/vpplink"
)

type ConnectivityServer struct {
	*common.RoutingData
	log *logrus.Entry

	providers        map[string]ConnectivityProvider
	connectivityMap  map[string]common.NodeConnectivity
	ipam             watchers.IpamCache
	FelixConfWatcher *watchers.FelixConfWatcher
	NodeWatcher      *watchers.NodeWatcher
	TunnelChangeChan chan TunnelChange
}

type TunnelChange struct {
	Swifindex  uint32
	ChangeType change
}

type change uint8

const (
	AddChange    change = 0
	DeleteChange change = 1
)

func NewConnectivityServer(routingData *common.RoutingData,
	ipam watchers.IpamCache,
	felixConfWatcher *watchers.FelixConfWatcher,
	nodeWatcher *watchers.NodeWatcher,
	log *logrus.Entry) *ConnectivityServer {
	server := ConnectivityServer{
		RoutingData:      routingData,
		log:              log,
		ipam:             ipam,
		FelixConfWatcher: felixConfWatcher,
		NodeWatcher:      nodeWatcher,
		connectivityMap:  make(map[string]common.NodeConnectivity),
	}

	providerData := NewConnectivityProviderData(server.Vpp, &server, log)

	server.providers = make(map[string]ConnectivityProvider)
	server.providers[FLAT] = NewFlatL3Provider(providerData)
	server.providers[IPIP] = NewIPIPProvider(providerData)
	server.providers[IPSEC] = NewIPsecProvider(providerData)
	server.providers[VXLAN] = NewVXLanProvider(providerData)
	server.providers[WIREGUARD] = NewWireguardProvider(providerData)

	server.TunnelChangeChan = providerData.tunnelChangeChan

	return &server
}

func (s *ConnectivityServer) GetAllTunnels() *[]uint32 {
	allTunnels := []uint32{}
	for _, provider := range s.providers {
		allTunnels = append(allTunnels, provider.GetSwifindexes()...)
	}
	return &allTunnels
}

func isCrossSubnet(gw net.IP, subnet net.IPNet) bool {
	return !subnet.Contains(gw)
}

func (s *ConnectivityServer) GetNodeIP(isv6 bool) net.IP {
	if isv6 {
		return s.Ipv6
	} else {
		return s.Ipv4
	}
}

func (s *ConnectivityServer) GetNodeIPNet(isv6 bool) *net.IPNet {
	if isv6 {
		return s.Ipv6Net
	} else {
		return s.Ipv4Net
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

func (s *ConnectivityServer) ServeConnectivity() error {
	for {
		evt := <-s.ConnectivityEventChan
		switch evt.Type {
		case common.ConnectivtyAdded:
			new := evt.New.(*common.NodeConnectivity)
			err := s.updateIPConnectivity(new, false /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while adding connectivity %s", err)
			}
		case common.ConnectivtyDeleted:
			old := evt.Old.(*common.NodeConnectivity)
			err := s.updateIPConnectivity(old, true /* isWithdraw */)
			if err != nil {
				s.log.Errorf("Error while deleting connectivity %s", err)
			}
		case common.NodeStateChanged:
			old := evt.Old.(*common.NodeState)
			new := evt.New.(*common.NodeState)
			if common.GetStringChangeType(old.Status.WireguardPublicKey, new.Status.WireguardPublicKey) > common.ChangeSame {
				s.updateAllIPConnectivity()
			}
			break
		case common.RescanState:
			for _, provider := range s.providers {
				provider.OnVppRestart()
				provider.RescanState()
			}
			break
		case common.VppRestart:
			for _, provider := range s.providers {
				provider.OnVppRestart()
			}
			for _, cn := range s.connectivityMap {
				s.log.Infof("Adding routing : %s", cn)
				err := s.updateIPConnectivity(&cn, false)
				if err != nil {
					s.log.Errorf("Error re-injecting connectivity %s : %v", cn, err)
				}
			}
			break
		case common.FelixConfChanged:
			old := evt.Old.(*calicov3.FelixConfigurationSpec)
			new := evt.New.(*calicov3.FelixConfigurationSpec)
			if old == nil || new == nil {
				/* First/last update, do nothing*/
				continue
			}
			if old.WireguardEnabled != new.WireguardEnabled {
				s.log.Infof("WireguardEnabled Changed")
				s.updateAllIPConnectivity()
			} else if old.WireguardListeningPort != new.WireguardListeningPort {
				s.log.Infof("WireguardListeningPort Changed")
				s.updateAllIPConnectivity()
			}
		case common.IpamConfChanged:
			old := evt.Old.(*calicov3.IPPool)
			new := evt.New.(*calicov3.IPPool)
			if old == nil || new == nil {
				/* First/last update, do nothing*/
				continue
			}
			if new.Spec.VXLANMode != old.Spec.VXLANMode ||
				new.Spec.IPIPMode != old.Spec.IPIPMode {
				s.log.Infof("VXLAN/IPIPMode Changed")
				s.updateAllIPConnectivity()
			}
		}
	}
	return nil
}

func (s *ConnectivityServer) getProviderType(cn *common.NodeConnectivity) string {
	ipPool := s.ipam.GetPrefixIPPool(&cn.Dst)
	if ipPool == nil {
		return FLAT
	}
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeAlways {
		if s.providers[IPSEC].Enabled() {
			return IPSEC
		} else if s.providers[WIREGUARD].Enabled() {
			return WIREGUARD
		} else {
			return IPIP
		}
	}
	ipNet := s.GetNodeIPNet(vpplink.IsIP6(cn.Dst.IP))
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeCrossSubnet && !isCrossSubnet(cn.NextHop, *ipNet) {
		if s.providers[IPSEC].Enabled() {
			return IPSEC
		} else if s.providers[WIREGUARD].Enabled() {
			return WIREGUARD
		} else {
			return IPIP
		}
	}
	if ipPool.Spec.VXLANMode == calicov3.VXLANModeAlways {
		return VXLAN
	}
	if ipPool.Spec.VXLANMode == calicov3.VXLANModeCrossSubnet && !isCrossSubnet(cn.NextHop, *ipNet) {
		return VXLAN
	}
	return FLAT
}

func (s *ConnectivityServer) updateIPConnectivity(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
	var providerType string
	if IsWithdraw {
		oldCn, found := s.connectivityMap[cn.String()]
		if !found {
			providerType = s.getProviderType(cn)
			s.log.Infof("Didnt find provider in map, trying :%s", providerType)
		} else {
			providerType = oldCn.ResolvedProvider
			delete(s.connectivityMap, oldCn.String())
			s.log.Infof("Deleting path (%s) %s", providerType, oldCn.String())
		}
		return s.providers[providerType].DelConnectivity(cn)
	} else {
		providerType = s.getProviderType(cn)
		oldCn, found := s.connectivityMap[cn.String()]
		if found {
			oldProviderType := oldCn.ResolvedProvider
			if oldProviderType != providerType {
				s.log.Infof("Path (%s) changed provider (%s->%s) %s", providerType, oldProviderType, providerType, cn.String())
				err := s.providers[oldProviderType].DelConnectivity(cn)
				if err != nil {
					s.log.Errorf("Error del connectivity when changing provider %s->%s : %s", oldProviderType, providerType, err)
				}
				cn.ResolvedProvider = providerType
				s.connectivityMap[cn.String()] = *cn
				return s.providers[providerType].AddConnectivity(cn)
			} else {
				s.log.Infof("Added same path (%s) %s", providerType, cn.String())
				return s.providers[providerType].AddConnectivity(cn)
			}
		} else {
			s.log.Infof("Added path (%s) %s", providerType, cn.String())
			cn.ResolvedProvider = providerType
			s.connectivityMap[cn.String()] = *cn
			return s.providers[providerType].AddConnectivity(cn)
		}
	}
}
