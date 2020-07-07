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

	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type CalicoServiceProvider struct {
	log          *logrus.Entry
	vpp          *vpplink.VppLink
	s            *Server
	clusterIPMap map[string]*types.CalicoTranslateEntry
	nodePortMap  map[string]*types.CalicoTranslateEntry
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
	p.clusterIPMap = make(map[string]*types.CalicoTranslateEntry)
	p.nodePortMap = make(map[string]*types.CalicoTranslateEntry)
	return nil
}

func getCalicoEntry(servicePort *v1.ServicePort, ep *v1.Endpoints, clusterIP net.IP) (entry *types.CalicoTranslateEntry, err error) {
	targetPort, err := getTargetPort(*servicePort)
	if err != nil {
		return nil, errors.Wrapf(err, "Error determinig target port")
	}
	backendIPs := getServiceBackendIPs(servicePort, ep)
	backends := make([]types.CalicoEndpointTuple, 0, len(backendIPs))
	for _, backendIP := range backendIPs {
		backends = append(backends, types.CalicoEndpointTuple{
			SrcEndpoint: types.CalicoEndpoint{},
			DstEndpoint: types.CalicoEndpoint{
				Port: uint16(targetPort),
				IP:   backendIP,
			},
		})
	}
	return &types.CalicoTranslateEntry{
		Proto: getServicePortProto(servicePort.Protocol),
		Endpoint: types.CalicoEndpoint{
			Port: uint16(servicePort.Port),
			IP:   clusterIP,
		},
		Backends: backends,
		IsRealIP: false,
	}, nil
}

func getCalicoNodePortEntry(servicePort *v1.ServicePort, ep *v1.Endpoints, nodeIP net.IP) (entry *types.CalicoTranslateEntry, err error) {
	targetPort, err := getTargetPort(*servicePort)
	if err != nil {
		return nil, errors.Wrapf(err, "Error determinig target port")
	}
	backendIPs := getServiceBackendIPs(servicePort, ep)
	backends := make([]types.CalicoEndpointTuple, 0, len(backendIPs))
	for _, backendIP := range backendIPs {
		backends = append(backends, types.CalicoEndpointTuple{
			SrcEndpoint: types.CalicoEndpoint{
				IP: nodeIP,
			},
			DstEndpoint: types.CalicoEndpoint{
				Port: uint16(targetPort),
				IP:   backendIP,
			},
		})
	}
	return &types.CalicoTranslateEntry{
		Proto: getServicePortProto(servicePort.Protocol),
		Endpoint: types.CalicoEndpoint{
			Port: uint16(servicePort.NodePort),
			IP:   nodeIP,
		},
		Backends: backends,
		IsRealIP: true,
	}, nil
}

func (p *CalicoServiceProvider) OnVppRestart() {
	for servicePortName, entry := range p.clusterIPMap {
		entryID, err := p.vpp.CalicoTranslateAdd(entry)
		if err != nil {
			p.log.Errorf("Error re-injecting entry %s : %v", entry.String(), err)
		} else {
			entry.ID = entryID
			p.clusterIPMap[servicePortName] = entry
		}
	}
	for servicePortName, entry := range p.nodePortMap {
		entryID, err := p.vpp.CalicoTranslateAdd(entry)
		if err != nil {
			p.log.Errorf("Error re-injecting entry %s : %v", entry.String(), err)
		} else {
			entry.ID = entryID
			p.nodePortMap[servicePortName] = entry
		}
	}
}

func (p *CalicoServiceProvider) AddServicePort(service *v1.Service, ep *v1.Endpoints, isNodePort bool) (err error) {
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	nodeIP := p.s.getNodeIP(vpplink.IsIP6(clusterIP))
	for _, servicePort := range service.Spec.Ports {
		if entry, err := getCalicoEntry(&servicePort, ep, clusterIP); err == nil {
			previousEntry, previousFound := p.clusterIPMap[servicePort.Name]
			if !previousFound || !entry.Equal(previousEntry) {
				p.log.Infof("(add) %s", entry.String())
				entryID, err := p.vpp.CalicoTranslateAdd(entry)
				if err != nil {
					return errors.Wrapf(err, "NAT:Error adding nodePort %s", entry.String())
				}
				entry.ID = entryID
				p.clusterIPMap[servicePort.Name] = entry
			} else {
				p.log.Debugf("(unchanged) %s", entry.String())
			}
		} else {
			p.log.Warnf("NAT:Error getting service entry: %v", err)
		}
		if !isNodePort {
			continue
		}
		if entry, err := getCalicoNodePortEntry(&servicePort, ep, nodeIP); err == nil {
			previousEntry, previousFound := p.nodePortMap[servicePort.Name]
			if !previousFound || !entry.Equal(previousEntry) {
				p.log.Infof("(add) %s", entry.String())
				entryID, err := p.vpp.CalicoTranslateAdd(entry)
				if err != nil {
					return errors.Wrapf(err, "NAT:Error adding nodePort %s", entry.String())
				}
				entry.ID = entryID
				p.nodePortMap[servicePort.Name] = entry
			} else {
				p.log.Debugf("(unchanged) %s", entry.String())
			}
		} else {
			p.log.Warnf("NAT:Error getting service entry: %v", err)
		}
	}
	return nil
}

func (p *CalicoServiceProvider) DelServicePort(service *v1.Service, ep *v1.Endpoints, isNodePort bool) (err error) {
	for _, servicePort := range service.Spec.Ports {
		if entry, ok := p.clusterIPMap[servicePort.Name]; ok {
			p.log.Infof("(del) %s", entry.String())
			err = p.vpp.CalicoTranslateDel(entry.ID)
			if err != nil {
				return errors.Wrapf(err, "(del) Error deleting entry %s", entry.String())
			}
			delete(p.clusterIPMap, servicePort.Name)
		} else {
			p.log.Infof("(del) Entry not found for %s", servicePort.Name)
		}
		if !isNodePort {
			continue
		}
		if entry, ok := p.nodePortMap[servicePort.Name]; ok {
			p.log.Infof("(del) nodeport %s", entry.String())
			err = p.vpp.CalicoTranslateDel(entry.ID)
			if err != nil {
				return errors.Wrapf(err, "(del) Error deleting nodeport %s", entry.String())
			}
			delete(p.clusterIPMap, servicePort.Name)
		} else {
			p.log.Infof("(del) Entry not found for %s", servicePort.Name)
		}
	}
	return nil
}
