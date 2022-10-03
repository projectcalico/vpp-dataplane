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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	CalicoAnnotationPrefix string = "cni.projectcalico.org/"
	VppAnnotationPrefix    string = "cni.projectcalico.org/vpp."
	MemifPortAnnotation    string = "memif.ports"
	TunTapPortAnnotation   string = "tuntap.ports"
	VclAnnotation          string = "vcl"
	SpoofAnnotation        string = "allowedSourcePrefixes"
	IfSpecAnnotation       string = "interfaceSpec"
)

func (s *Server) ParsePortSpec(value string) (ifPortConfigs *storage.LocalIfPortConfigs, err error) {
	ifPortConfigs = &storage.LocalIfPortConfigs{}
	parts := strings.Split(value, ":") /* tcp:1234[-4567] */
	if len(parts) != 2 {
		return nil, fmt.Errorf("Value should start with protocol e.g. 'tcp:'")
	}
	ifPortConfigs.Proto, err = types.UnformatProto(parts[0])
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing proto %s", parts[0])
	}

	portParts := strings.Split(parts[1], "-") /* tcp:1234[-4567] */
	if len(portParts) != 2 && len(portParts) != 1 {
		return nil, fmt.Errorf("Please specify a port or a port range e.g. '1234-5678'")
	}

	start, err := strconv.ParseInt(portParts[0], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing port %s", portParts[0])
	}
	ifPortConfigs.Start = uint16(start)
	ifPortConfigs.End = uint16(start)

	if len(portParts) == 2 {
		end, err := strconv.ParseInt(portParts[1], 10, 32)
		if err != nil {
			return nil, errors.Wrapf(err, "Error parsing end port %s", portParts[1])
		}
		ifPortConfigs.End = uint16(end)
	}
	return ifPortConfigs, nil
}

func (s *Server) ParsePortMappingAnnotation(podSpec *storage.LocalPodSpec, ifType storage.VppInterfaceType, value string) (err error) {
	if podSpec.PortFilteredIfType != storage.VppIfTypeUnknown && podSpec.PortFilteredIfType != ifType {
		return fmt.Errorf("Cannot use port filters on different interface type")
	}
	podSpec.PortFilteredIfType = ifType
	// value is expected to be like "tcp:1234-1236,udp:4456"
	portSpecs := strings.Split(value, ",")
	for idx, portSpec := range portSpecs {
		ifPortConfig, err := s.ParsePortSpec(portSpec)
		if err != nil {
			return errors.Wrapf(err, "Error parsing portSpec[%d] %s", idx, portSpec)
		}
		podSpec.IfPortConfigs = append(podSpec.IfPortConfigs, *ifPortConfig)
	}
	return nil
}

func (s *Server) ParseDefaultIfType(podSpec *storage.LocalPodSpec, ifType storage.VppInterfaceType) (err error) {
	if podSpec.DefaultIfType != storage.VppIfTypeUnknown && podSpec.DefaultIfType != ifType {
		return fmt.Errorf("Cannot set two different default interface type")
	}
	podSpec.DefaultIfType = ifType
	return nil
}

func (s *Server) ParseEnableDisableAnnotation(value string) (bool, error) {
	switch value {
	case "enable":
		return true, nil
	case "disable":
		return false, nil
	default:
		return false, errors.Errorf("Unknown value %s", value)
	}
}

func (s *Server) ParseTrueFalseAnnotation(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.Errorf("Unknown value %s", value)
	}
}

func (s *Server) ParseSpoofAddressAnnotation(value string) ([]cnet.IPNet, error) {
	var requestedSourcePrefixes []string
	var allowedSources []cnet.IPNet
	err := json.Unmarshal([]byte(value), &requestedSourcePrefixes)
	if err != nil {
		return nil, errors.Errorf("failed to parse '%s' as JSON: %s", value, err)
	}
	for _, prefix := range requestedSourcePrefixes {
		var ipn *cnet.IPNet
		_, ipn, err = cnet.ParseCIDROrIP(prefix)
		if err != nil {
			return nil, err
		}
		allowedSources = append(allowedSources, *(ipn.Network()))
	}
	return allowedSources, nil
}

func (s *Server) ParseInterfaceSpec(value string) (map[string]config.InterfaceSpec, error) {
	var interfaceSpecs map[string]config.InterfaceSpec
	err := json.Unmarshal([]byte(value), &interfaceSpecs)
	if err != nil {
		return nil, errors.Errorf("failed to parse '%s' as JSON: %s", value, err)
	}
	return interfaceSpecs, nil
}

func GetDefaultIfSpec(isL3 bool) config.InterfaceSpec {
	return config.InterfaceSpec{
		NumRxQueues: config.DefaultInterfaceSpec.NumRxQueues,
		NumTxQueues: config.DefaultInterfaceSpec.NumTxQueues,
		RxQueueSize: config.DefaultInterfaceSpec.RxQueueSize,
		TxQueueSize: config.DefaultInterfaceSpec.TxQueueSize,
		IsL3:        isL3,
	}
}

func (s *Server) ParsePodAnnotations(podSpec *storage.LocalPodSpec, annotations map[string]string) (err error) {
	for key, value := range annotations {
		if key == CalicoAnnotationPrefix+SpoofAnnotation {
			podSpec.AllowedSpoofingPrefixes = annotations[CalicoAnnotationPrefix+SpoofAnnotation]
		}
		if !strings.HasPrefix(key, VppAnnotationPrefix) {
			continue
		}
		switch key {
		case VppAnnotationPrefix + IfSpecAnnotation:
			var ifSpecs map[string]config.InterfaceSpec
			ifSpecs, err = s.ParseInterfaceSpec(value)
			if err != nil {
				s.log.Warnf("Error parsing key %s %s", key, err)
			}
			if podSpec.InterfaceName == "eth0" && podSpec.NetworkName == "" { // double check to be sure
				eth0Spec, found := ifSpecs["eth0"]
				if found {
					podSpec.HasSpecificTunTapIfSpec = true
					podSpec.TunTapIfSpec = eth0Spec
					s.log.Infof("eth0:: %+v", eth0Spec)
				}
				memif0Spec, found := ifSpecs["memif0"]
				if found {
					podSpec.HasSpecificMemifIfSpec = true
					podSpec.MemifIfSpec = memif0Spec
					s.log.Infof("memif0:: %+v", memif0Spec)
				}
			} else {
				ethSpec, found := ifSpecs[podSpec.InterfaceName]
				if found {
					if podSpec.EnableMemif {
						podSpec.MemifIfSpec = ethSpec
						podSpec.HasSpecificMemifIfSpec = true
					} else {
						podSpec.TunTapIfSpec = ethSpec
						podSpec.HasSpecificTunTapIfSpec = true
					}
					s.log.Infof("%s:: %+v", podSpec.InterfaceName, ethSpec)
				}
			}
			s.log.Infof("%+v", ifSpecs)

		case VppAnnotationPrefix + MemifPortAnnotation:
			podSpec.EnableMemif = true
			if value == "default" {
				err = s.ParseDefaultIfType(podSpec, storage.VppIfTypeMemif)
			} else {
				err = s.ParsePortMappingAnnotation(podSpec, storage.VppIfTypeMemif, value)
			}
		case VppAnnotationPrefix + TunTapPortAnnotation:
			if value == "default" {
				err = s.ParseDefaultIfType(podSpec, storage.VppIfTypeTunTap)
			} else {
				err = s.ParsePortMappingAnnotation(podSpec, storage.VppIfTypeTunTap, value)
			}
		case VppAnnotationPrefix + VclAnnotation:
			podSpec.EnableVCL, err = s.ParseEnableDisableAnnotation(value)
		default:
			continue
		}
		if err != nil {
			s.log.Warnf("Error parsing key %s %s", key, err)
		}
	}
	return nil
}
