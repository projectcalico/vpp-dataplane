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
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func getTargetPort(sPort v1.ServicePort, epPort *v1.EndpointPort) (int32, error) {
	tp := sPort.TargetPort
	if tp.Type == intstr.Int {
		if tp.IntVal == 0 {
			// Unset targetport
			return sPort.Port, nil
		} else {
			return tp.IntVal, nil
		}
	} else {
		return epPort.Port, nil
	}
}

func getServicePortProto(proto v1.Protocol) types.IPProto {
	switch proto {
	case v1.ProtocolUDP:
		return types.UDP
	case v1.ProtocolSCTP:
		return types.SCTP
	case v1.ProtocolTCP:
		return types.TCP
	default:
		return types.TCP
	}
}

func formatProto(proto types.IPProto) string {
	switch proto {
	case types.UDP:
		return "UDP"
	case types.SCTP:
		return "SCTP"
	case types.TCP:
		return "TCP"
	default:
		return "???"
	}
}

func getServiceBackends(servicePort *v1.ServicePort, ep *v1.Endpoints, localOnly bool, flagNonLocal bool) (backends []types.CnatEndpointTuple, err error) {
	backends = make([]types.CnatEndpointTuple, 0)

	for _, set := range ep.Subsets {
		// Check if this subset exposes the port we're interested in
		for _, port := range set.Ports {
			if servicePort.Name == port.Name {
				for _, addr := range set.Addresses {
					isLocal := true
					if addr.NodeName != nil && *addr.NodeName != config.NodeName {
						isLocal = false
					}
					flags := uint8(0)
					if !isLocal {
						if localOnly {
							continue
						}
						if flagNonLocal {
							flags = flags | types.CnatNoNat
						}
					}
					ip := net.ParseIP(addr.IP)
					if ip == nil {
						continue
					}
					targetPort, err := getTargetPort(*servicePort, &port)
					if err != nil {
						return nil, errors.Wrapf(err, "Error determinig target port")
					}
					backends = append(backends, types.CnatEndpointTuple{
						DstEndpoint: types.CnatEndpoint{
							Port: uint16(targetPort),
							IP:   ip,
						},
						Flags: flags,
					})
				}
				break
			}
		}
	}
	return backends, nil
}
