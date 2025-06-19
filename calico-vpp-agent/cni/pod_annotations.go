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

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	CalicoAnnotationPrefix string = "cni.projectcalico.org/"
	VppAnnotationPrefix    string = "cni.projectcalico.org/vpp"
	MemifPortAnnotation    string = "ExtraMemifPorts"
	VclAnnotation          string = "Vcl"
	SpoofAnnotation        string = "AllowedSourcePrefixes"
	IfSpecAnnotation       string = "InterfacesSpec"
	IfSpecPBLAnnotation    string = "ExtraMemifSpec"
)

func (s *Server) ParsePortSpec(value string) (ifPortConfigs *storage.LocalIfPortConfigs, err error) {
	ifPortConfigs = &storage.LocalIfPortConfigs{}
	parts := strings.Split(value, ":") /* tcp:1234[-4567] */
	if len(parts) != 2 {
		return nil, fmt.Errorf("value should start with protocol e.g. 'tcp:'")
	}
	ifPortConfigs.Proto, err = types.UnformatProto(parts[0])
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing proto %s", parts[0])
	}

	portParts := strings.Split(parts[1], "-") /* tcp:1234[-4567] */
	if len(portParts) != 2 && len(portParts) != 1 {
		return nil, fmt.Errorf("please specify a port or a port range e.g. '1234-5678'")
	}

	start, err := strconv.ParseUint(portParts[0], 10, 16)
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing port %s", portParts[0])
	}
	ifPortConfigs.Start = uint16(start)
	ifPortConfigs.End = uint16(start)

	if len(portParts) == 2 {
		end, err := strconv.ParseUint(portParts[1], 10, 16)
		if err != nil {
			return nil, errors.Wrapf(err, "Error parsing end port %s", portParts[1])
		}
		ifPortConfigs.End = uint16(end)
	}
	return ifPortConfigs, nil
}

func (s *Server) ParsePortMappingAnnotation(podSpec *storage.LocalPodSpec, ifType storage.VppInterfaceType, value string) (err error) {
	if podSpec.PortFilteredIfType != storage.VppIfTypeUnknown && podSpec.PortFilteredIfType != ifType {
		return fmt.Errorf("cannot use port filters on different interface type")
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
		return fmt.Errorf("cannot set two different default interface type")
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

func GetDefaultIfSpec(isL3 bool) config.InterfaceSpec {
	return config.InterfaceSpec{
		NumRxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumRxQueues,
		NumTxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumTxQueues,
		RxQueueSize: vpplink.DefaultIntTo(config.GetCalicoVppInterfaces().DefaultPodIfSpec.RxQueueSize, vpplink.CalicoVppDefaultQueueSize),
		TxQueueSize: vpplink.DefaultIntTo(config.GetCalicoVppInterfaces().DefaultPodIfSpec.TxQueueSize, vpplink.CalicoVppDefaultQueueSize),
		IsL3:        &isL3,
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
			err = json.Unmarshal([]byte(value), &ifSpecs)
			if err != nil {
				s.log.Warnf("Error parsing key %s %s", key, err)
			}
			for _, ifSpec := range ifSpecs {
				if err := ifSpec.Validate(config.GetCalicoVppInterfaces().MaxPodIfSpec); err != nil {
					s.log.Error("Pod interface config exceeds max config")
					return err
				}
			}
			if ethSpec, found := ifSpecs[podSpec.InterfaceName]; found {
				podSpec.IfSpec = ethSpec
				isL3 := podSpec.IfSpec.GetIsL3(isMemif(podSpec.InterfaceName))
				podSpec.IfSpec.IsL3 = &isL3
			}

		case VppAnnotationPrefix + MemifPortAnnotation:
			podSpec.EnableMemif = true
			err = s.ParsePortMappingAnnotation(podSpec, storage.VppIfTypeMemif, value)
			if err != nil {
				return err
			}
			err = s.ParseDefaultIfType(podSpec, storage.VppIfTypeTunTap)
		case VppAnnotationPrefix + IfSpecPBLAnnotation:
			var ifSpec *config.InterfaceSpec
			err := json.Unmarshal([]byte(value), &ifSpec)
			if err != nil {
				s.log.Warnf("Error parsing key %s %s", key, err)
			}
			err = ifSpec.Validate(config.GetCalicoVppInterfaces().MaxPodIfSpec)
			if err != nil {
				s.log.Error("PBL Memif interface config exceeds max config")
				return err
			}
			podSpec.PBLMemifSpec = *ifSpec
			isL3 := podSpec.PBLMemifSpec.GetIsL3(true)
			podSpec.PBLMemifSpec.IsL3 = &isL3
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
