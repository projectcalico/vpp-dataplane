// Copyright (C) 2019 Cisco Systems Inc.
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

package services

import (
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type CalicoServiceProvider struct {
	log      *logrus.Entry
	vpp      *vpplink.VppLink
	s        *Server
	stateMap map[string]*types.CnatTranslateEntry
}

func newCalicoServiceProvider(s *Server) (p *CalicoServiceProvider) {
	p = &CalicoServiceProvider{
		log: s.log,
		vpp: s.vpp,
		s:   s,
	}
	return p
}

func (p *CalicoServiceProvider) Init() (err error) {
	p.stateMap = make(map[string]*types.CnatTranslateEntry)
	return nil
}

// | or # should never appear in an IP or in a service / port name which should be a valid DNS name
func nodePortKey(serviceID, portName string) string {
	return "NP|" + serviceID + "##" + portName
}

func clusterIPKey(serviceID, portName string) string {
	return "C|" + serviceID + "##" + portName
}

func extIPKey(externalIP, serviceID, portName string) string {
	return "E|" + serviceID + "##" + externalIP + "##" + portName
}

func getCalicoEntry(servicePort *v1.ServicePort, ep *v1.Endpoints, clusterIP net.IP, localOnly bool) (entry *types.CnatTranslateEntry, err error) {
	backends, err := getServiceBackends(servicePort, ep, localOnly, config.EnableMaglev)
	if err != nil {
		return nil, err
	}

	tr := &types.CnatTranslateEntry{
		Proto: getServicePortProto(servicePort.Protocol),
		Endpoint: types.CnatEndpoint{
			Port: uint16(servicePort.Port),
			IP:   clusterIP,
		},
		Backends: backends,
		IsRealIP: false,
		LbType:   types.DefaultLB,
	}
	if config.EnableMaglev {
		tr.LbType = types.MaglevLB
	}
	return tr, nil
}

func getCalicoNodePortEntry(servicePort *v1.ServicePort, ep *v1.Endpoints, nodeIP net.IP, localOnly bool) (entry *types.CnatTranslateEntry, err error) {
	backends, err := getServiceBackends(servicePort, ep, localOnly, false /* flagNonLocal */)
	if err != nil {
		return nil, err
	}

	for _, backend := range backends {
		backend.SrcEndpoint.IP = nodeIP
	}
	tr := &types.CnatTranslateEntry{
		Proto: getServicePortProto(servicePort.Protocol),
		Endpoint: types.CnatEndpoint{
			Port: uint16(servicePort.NodePort),
			IP:   nodeIP,
		},
		Backends: backends,
		IsRealIP: true,
		LbType:   types.DefaultLB,
	}

	if config.EnableMaglev {
		tr.LbType = types.MaglevLB
	}
	return tr, nil
}

func (p *CalicoServiceProvider) OnVppRestart() {
	newState := make(map[string]*types.CnatTranslateEntry)
	for key, entry := range p.stateMap {
		entryID, err := p.vpp.CnatTranslateAdd(entry)
		if err != nil {
			p.log.Errorf("Error re-injecting cnat entry %s : %v", entry.String(), err)
		} else {
			entry.ID = entryID
			newState[key] = entry
		}
	}
	p.stateMap = newState
}

func (p *CalicoServiceProvider) updateCnatEntry(key string, entry *types.CnatTranslateEntry) (err error) {
	previousEntry, previousFound := p.stateMap[key]
	if !previousFound || !entry.Equal(previousEntry) {
		p.log.Infof("(add) %s", entry.String())
		entryID, err := p.vpp.CnatTranslateAdd(entry)
		if err != nil {
			return errors.Wrapf(err, "NAT:Error adding translation %s", entry.String())
		}
		entry.ID = entryID
		p.stateMap[key] = entry
	} else {
		p.log.Debugf("(unchanged) %s", entry.String())
	}
	return nil
}

func (p *CalicoServiceProvider) AddServicePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	nodeIP := p.s.getNodeIP(vpplink.IsIP6(clusterIP))
	localOnly := service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal
	serviceID := service.ObjectMeta.GetSelfLink()

	for _, servicePort := range service.Spec.Ports {
		// Service ClusterIP handling
		if clusterIP != nil {
			if entry, err := getCalicoEntry(&servicePort, ep, clusterIP, localOnly); err == nil {
				stateKey := clusterIPKey(serviceID, servicePort.Name)
				err = p.updateCnatEntry(stateKey, entry)
				if err != nil {
					return err
				}
			} else {
				p.log.Warnf("NAT:Error getting service entry: %v", err)
			}
		}

		// ExternalIPs handling
		for _, eip := range service.Spec.ExternalIPs {
			if extIP := net.ParseIP(eip); extIP != nil {
				if entry, err := getCalicoEntry(&servicePort, ep, extIP, localOnly); err == nil {
					stateKey := extIPKey(eip, serviceID, servicePort.Name)
					err = p.updateCnatEntry(stateKey, entry)
					if err != nil {
						return err
					}
				} else {
					p.log.Warnf("NAT:Error getting service entry: %v", err)
				}
			}
		}

		// NodePort redirection handling
		if service.Spec.Type != v1.ServiceTypeNodePort {
			continue
		}
		if entry, err := getCalicoNodePortEntry(&servicePort, ep, nodeIP, localOnly); err == nil {
			stateKey := nodePortKey(serviceID, servicePort.Name)
			err = p.updateCnatEntry(stateKey, entry)
			if err != nil {
				return err
			}
		} else {
			p.log.Warnf("NAT:Error getting service entry: %v", err)
		}
	}
	return nil
}

func (p *CalicoServiceProvider) DelServicePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	serviceID := service.ObjectMeta.GetSelfLink()

	for _, servicePort := range service.Spec.Ports {
		entries := make([]string, 0)
		if net.ParseIP(service.Spec.ClusterIP) != nil {
			entries = append(entries, clusterIPKey(serviceID, servicePort.Name))
		}
		for _, eip := range service.Spec.ExternalIPs {
			if extIP := net.ParseIP(eip); extIP != nil {
				entries = append(entries, extIPKey(eip, serviceID, servicePort.Name))
			}
		}
		if service.Spec.Type != v1.ServiceTypeNodePort {
			entries = append(entries, nodePortKey(serviceID, servicePort.Name))
		}

		for _, key := range entries {
			if entry, ok := p.stateMap[key]; ok {
				p.log.Infof("(del) %s", entry.String())
				err = p.vpp.CnatTranslateDel(entry.ID)
				if err != nil {
					return errors.Wrapf(err, "(del) Error deleting entry %s", entry.String())
				}
				delete(p.stateMap, key)
			} else {
				p.log.Errorf("(del) Entry not found for %s", key)
			}
		}
	}
	return nil
}
