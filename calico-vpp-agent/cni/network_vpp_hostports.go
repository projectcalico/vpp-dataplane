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

package cni

import (
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// getHostPortHostIP returns the hostIP for a given
// hostIP strings and an IP family
func (s *Server) getHostPortHostIP(hostIP net.IP, isIP6 bool) net.IP {
	if hostIP != nil && !hostIP.IsUnspecified() {
		if (hostIP.To4() == nil) == isIP6 {
			return hostIP
		}
	} else if s.nodeBGPSpec != nil {
		if isIP6 && s.nodeBGPSpec.IPv6Address != nil {
			return s.nodeBGPSpec.IPv6Address.IP
		} else if !isIP6 && s.nodeBGPSpec.IPv4Address != nil {
			return s.nodeBGPSpec.IPv4Address.IP
		}
	}
	return net.IP{}
}

func (s *Server) AddHostPort(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack) error {
	for _, hostPort := range podSpec.HostPorts {
		for _, containerAddr := range podSpec.ContainerIPs {
			hostIP := s.getHostPortHostIP(hostPort.HostIP, vpplink.IsIP6(containerAddr))
			if hostIP != nil && !hostIP.IsUnspecified() {
				entry := &types.CnatTranslateEntry{
					Endpoint: types.CnatEndpoint{
						IP:   hostIP,
						Port: hostPort.HostPort,
					},
					Backends: []types.CnatEndpointTuple{{
						DstEndpoint: types.CnatEndpoint{
							Port: hostPort.ContainerPort,
							IP:   containerAddr,
						},
					}},
					IsRealIP: true,
					Proto:    hostPort.Protocol,
					LbType:   types.DefaultLB,
				}
				s.log.Infof("pod(add) hostport %s", entry.String())
				id, err := s.vpp.CnatTranslateAdd(entry)
				if err != nil {
					return err
				} else {
					stack.Push(s.vpp.CnatTranslateDel, id)
				}
				if _, found := podSpec.HostPortEntryIDs[hostPort.HostPort]; !found {
					podSpec.HostPortEntryIDs[hostPort.HostPort] = make(map[string]uint32)
				}
				podSpec.HostPortEntryIDs[hostPort.HostPort][hostIP.String()] = id
			}
		}
	}
	return nil
}

func (s *Server) DelHostPort(podSpec *model.LocalPodSpec) {
	initialSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if ok {
		for hostport, entryIDs := range initialSpec.HostPortEntryIDs {
			for _, entryID := range entryIDs {
				err := s.vpp.CnatTranslateDel(entryID)
				if err != nil {
					s.log.Errorf("(del) Error deleting entry with ID %d: %v", entryID, err)
				}
				s.log.Infof("pod(del) hostport entry=%d for hostport=%d", entryID, hostport)
			}
		}
	} else {
		s.log.Warnf("Initial spec not found")
	}
}
