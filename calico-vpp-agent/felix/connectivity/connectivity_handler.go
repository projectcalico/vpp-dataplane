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
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

type ConnectivityHandler struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	providers         map[string]ConnectivityProvider
	connectivityMap   map[string]common.NodeConnectivity
	nodeByWGPublicKey map[string]string
}

func NewConnectivityHandler(vpp *vpplink.VppLink, cache *cache.Cache, clientv3 calicov3cli.Interface, log *logrus.Entry) *ConnectivityHandler {
	return &ConnectivityHandler{
		log:             log,
		vpp:             vpp,
		cache:           cache,
		connectivityMap: make(map[string]common.NodeConnectivity),
		providers: map[string]ConnectivityProvider{
			FLAT:      NewFlatL3Provider(vpp, log),
			IPIP:      NewIPIPProvider(vpp, cache, log),
			IPSEC:     NewIPsecProvider(vpp, cache, log),
			VXLAN:     NewVXLanProvider(vpp, cache, log),
			WIREGUARD: NewWireguardProvider(vpp, clientv3, cache, log),
			SRv6:      NewSRv6Provider(vpp, clientv3, cache, log),
		},
		nodeByWGPublicKey: make(map[string]string),
	}
}

type change uint8

const (
	AddChange    change = 0
	DeleteChange change = 1
)

func (s *ConnectivityHandler) UpdateAllIPConnectivity() {
	s.log.Infof("connectivity(upd) ipamConf Changed")
	for _, cn := range s.connectivityMap {
		err := s.UpdateIPConnectivity(&cn, false /* isWithdraw */)
		if err != nil {
			s.log.Errorf("Error while re-updating connectivity %s", err)
		}
	}
}

func (s *ConnectivityHandler) OnFelixConfChanged(old, new *felixConfig.Config) {
	if new == nil || old == nil {
		// First/last update, do nothing more
		return
	}
	if old.WireguardEnabled != new.WireguardEnabled {
		s.log.Infof("connectivity(upd) WireguardEnabled Changed %t->%t", old.WireguardEnabled, new.WireguardEnabled)
		s.providers[WIREGUARD].EnableDisable(new.WireguardEnabled)
		s.UpdateAllIPConnectivity()
	} else if old.WireguardListeningPort != new.WireguardListeningPort {
		s.log.Warnf("connectivity(upd) WireguardListeningPort Changed [NOT IMPLEMENTED]")
	}
}

func (s *ConnectivityHandler) OnIpamConfChanged(old, new *proto.IPAMPool) {
	s.UpdateAllIPConnectivity()
}

func (s *ConnectivityHandler) OnPeerNodeStateChanged(old, new *common.LocalNodeSpec) {
	if old != nil {
		if old.IPv4Address != nil {
			delete(s.cache.NodeByAddr, old.IPv4Address.IP.String())
		}
		if old.IPv6Address != nil {
			delete(s.cache.NodeByAddr, old.IPv6Address.IP.String())
		}
	}
	if new != nil {
		if new.IPv4Address != nil {
			s.cache.NodeByAddr[new.IPv4Address.IP.String()] = *new
		}
		if new.IPv6Address != nil {
			s.cache.NodeByAddr[new.IPv6Address.IP.String()] = *new
		}
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PeerNodeStateChanged,
		Old:  old,
		New:  new,
	})
}

func (s *ConnectivityHandler) UpdateSRv6Policy(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
	s.log.Infof("updateSRv6Policy")
	providerType := SRv6
	if IsWithdraw {
		err = s.providers[providerType].DelConnectivity(cn)
	} else {
		err = s.providers[providerType].AddConnectivity(cn)
	}
	return err
}

func (s *ConnectivityHandler) getProviderType(cn *common.NodeConnectivity) (string, error) {
	// use vxlan tunnel if secondary network, no need for ippool
	if cn.Vni != 0 {
		return VXLAN, nil
	}
	ipPool := s.cache.GetPrefixIPPool(&cn.Dst)
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
	nodeIPNet := s.cache.GetNodeIPNet(vpplink.IsIP6(cn.Dst.IP))
	if ipPool.IpipMode == encap.CrossSubnet {
		if nodeIPNet == nil {
			return FLAT, fmt.Errorf("missing node IPnet")
		}
		if !nodeIPNet.Contains(cn.NextHop) {
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
		if nodeIPNet == nil {
			return FLAT, fmt.Errorf("missing node IPnet")
		}
		if !nodeIPNet.Contains(cn.NextHop) {
			if s.providers[WIREGUARD].Enabled(cn) {
				return WIREGUARD, nil
			}
			return VXLAN, nil
		}
	}
	return FLAT, nil
}

func (s *ConnectivityHandler) UpdateIPConnectivity(cn *common.NodeConnectivity, IsWithdraw bool) (err error) {
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
func (s *ConnectivityHandler) ForceRescanState(providerType string) (err error) {
	provider, found := s.providers[providerType]
	if !found {
		return fmt.Errorf("can't find connectivity provider of type %s", providerType)
	}
	provider.RescanState()
	return nil
}

// ForceProviderEnableDisable force to enable/disable specific connectivity provider.
// The usage is mainly for testing purposes.
func (s *ConnectivityHandler) ForceProviderEnableDisable(providerType string, enable bool) (err error) {
	provider, found := s.providers[providerType]
	if !found {
		return fmt.Errorf("can't find connectivity provider of type %s", providerType)
	}
	provider.EnableDisable(enable)
	return nil
}

// TODO get rid (if possible) of all this "Force" methods by refactor the test code
//  (run the Server.ServeConnectivity(...) function and send into it events with common.SendEvent(...))

// ForceNodeAddition will add other node information as provided by calico configuration
// The usage is mainly for testing purposes.
func (s *ConnectivityHandler) ForceNodeAddition(newNode common.LocalNodeSpec, newNodeIP net.IP) {
	s.cache.NodeByAddr[newNodeIP.String()] = newNode
}

// ForceWGPublicKeyAddition will add other node information as provided by calico configuration
// The usage is mainly for testing purposes.
func (s *ConnectivityHandler) ForceWGPublicKeyAddition(newNode string, wgPublicKey string) {
	wgProvider, ok := s.providers[WIREGUARD].(*WireguardProvider)
	if !ok {
		panic("Type is not WireguardProvider")
	}
	wgProvider.NodesToWGPublicKey[newNode] = wgPublicKey
}

func (s *ConnectivityHandler) OnWireguardEndpointUpdate(msg *proto.WireguardEndpointUpdate) (err error) {
	s.log.Infof("Received wireguard public key %+v", msg)
	var old *common.NodeWireguardPublicKey
	_, ok := s.nodeByWGPublicKey[msg.Hostname]
	if ok {
		old = &common.NodeWireguardPublicKey{
			Name:               msg.Hostname,
			WireguardPublicKey: s.nodeByWGPublicKey[msg.Hostname],
		}
	} else {
		old = &common.NodeWireguardPublicKey{Name: msg.Hostname}
	}
	new := &common.NodeWireguardPublicKey{
		Name:               msg.Hostname,
		WireguardPublicKey: msg.PublicKey,
	}

	wgProvider, ok := s.providers[WIREGUARD].(*WireguardProvider)
	if !ok {
		panic("Type is not WireguardProvider")
	}
	wgProvider.NodesToWGPublicKey[new.Name] = new.WireguardPublicKey
	change := common.GetStringChangeType(old.WireguardPublicKey, new.WireguardPublicKey)
	if change != common.ChangeSame {
		s.log.Infof("connectivity(upd) WireguardPublicKey Changed (%s) %s->%s", old.Name, old.WireguardPublicKey, new.WireguardPublicKey)
		s.UpdateAllIPConnectivity()
	}
	return nil
}

func (s *ConnectivityHandler) OnWireguardEndpointRemove(msg *proto.WireguardEndpointRemove) (err error) {
	return nil
}

func (s *ConnectivityHandler) ConnectivityHandlerInit() error {
	// There might be leftover state in VPP in case we
	// restarted so first check what is present
	for _, provider := range s.providers {
		provider.RescanState()
	}
	return nil
}
