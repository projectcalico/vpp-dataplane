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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (s *Server) BindHostPort(port storage.HostPortBinding, containerIp net.IP, stack *vpplink.CleanupStack) (id uint32, err error){
	hostIp := port.HostIP
	hostPort := port.HostPort
	containerPort := port.ContainerPort

	entry := &types.CnatTranslateEntry{
		Endpoint: types.CnatEndpoint{
			IP:   hostIp,
			Port: uint16(hostPort),
		},
		Backends: []types.CnatEndpointTuple{
			{
				DstEndpoint: types.CnatEndpoint{
					Port: uint16(containerPort),
					IP:   containerIp,
				},
			},
		},
		IsRealIP: true,
		Proto:    types.TCP,
		LbType:   types.DefaultLB,
	}
	s.log.Infof("(add) %s", entry.String())
	id, err = s.vpp.CnatTranslateAdd(entry)
	if err != nil {
		errors.Wrapf(err, "Error binding hostport: Error re-injecting cnat entry %s", entry.String())
		return 0, err
	} else {
		stack.Push(s.vpp.CnatTranslateAdd, entry)
		return id, err
	}
}

func (s *Server) AddHostPort(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) error{
	for idx, hostPort := range podSpec.HostPorts {
		for _, containerAddr := range podSpec.ContainerIps {
			if !vpplink.AddrFamilyDiffers(containerAddr.IP, hostPort.HostIP) {
				continue
			}
			id, err := s.BindHostPort(hostPort, containerAddr.IP, stack)
			podSpec.HostPorts[idx].EntryID = id
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) DelHostPort(podSpec *storage.LocalPodSpec) {
	initialSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if ok {
		for _, hostport := range initialSpec.HostPorts {
			err := s.vpp.CnatTranslateDel(hostport.EntryID)
			if err != nil {
				s.log.Errorf("(del) Error deleting entry with ID %s: %v", hostport.EntryID, err)
			}
			s.log.Infof("Entry %s deleted", hostport.EntryID)
		}
	} else {
		s.log.Warnf("Initial spec not found")
	}
}