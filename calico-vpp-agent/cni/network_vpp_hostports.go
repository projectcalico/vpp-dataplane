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

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (s *Server) AddHostPort(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) error {
	for idx, hostPort := range podSpec.HostPorts {
		for _, containerAddr := range podSpec.ContainerIps {
			for _, hostIP := range []net.IP{hostPort.HostIP4, hostPort.HostIP6} {
				if hostIP != nil {
					if !vpplink.AddrFamilyDiffers(containerAddr.IP, hostIP) {
						continue
					}
					entry := &types.CnatTranslateEntry{
						Endpoint: types.CnatEndpoint{
							IP:   hostIP,
							Port: hostPort.HostPort,
						},
						Backends: []types.CnatEndpointTuple{{
							DstEndpoint: types.CnatEndpoint{
								Port: hostPort.ContainerPort,
								IP:   containerAddr.IP,
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
					podSpec.HostPorts[idx].EntryID = id
				}
			}
		}
	}
	return nil
}

func (s *Server) DelHostPort(podSpec *storage.LocalPodSpec) {
	initialSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if ok {
		for _, hostPort := range initialSpec.HostPorts {
			err := s.vpp.CnatTranslateDel(hostPort.EntryID)
			if err != nil {
				s.log.Errorf("(del) Error deleting entry with ID %d: %v", hostPort.EntryID, err)
			}
			s.log.Infof("pod(del) hostport entry=%d", hostPort.EntryID)
		}
	} else {
		s.log.Warnf("Initial spec not found")
	}
}
