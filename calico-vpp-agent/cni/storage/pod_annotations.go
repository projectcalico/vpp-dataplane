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

package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func parsePortSpec(value string) (ifPortConfigs *LocalIfPortConfigs, err error) {
	ifPortConfigs = &LocalIfPortConfigs{}
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

func parsePortMappingAnnotation(podSpec *LocalPodSpec, ifType VppInterfaceType, value string) (err error) {
	if podSpec.PortFilteredIfType != VppIfTypeUnknown && podSpec.PortFilteredIfType != ifType {
		return fmt.Errorf("Cannot use port filters on different interface type")
	}
	podSpec.PortFilteredIfType = ifType
	// value is expected to be like "tcp:1234-1236,udp:4456"
	portSpecs := strings.Split(value, ",")
	for idx, portSpec := range portSpecs {
		ifPortConfig, err := parsePortSpec(portSpec)
		if err != nil {
			return errors.Wrapf(err, "Error parsing portSpec[%d] %s", idx, portSpec)
		}
		podSpec.IfPortConfigs = append(podSpec.IfPortConfigs, *ifPortConfig)
	}
	return nil
}

func parseDefaultIfType(podSpec *LocalPodSpec, ifType VppInterfaceType) (err error) {
	if podSpec.DefaultIfType != VppIfTypeUnknown && podSpec.DefaultIfType != ifType {
		return fmt.Errorf("Cannot set two different default interface type")
	}
	podSpec.DefaultIfType = ifType
	return nil
}

func parseEnableDisableAnnotation(value string) (bool, error) {
	switch value {
	case "enable":
		return true, nil
	case "disable":
		return false, nil
	default:
		return false, errors.Errorf("Unknown value %s", value)
	}
}

func parseSpoofAddressAnnotation(value string) ([]net.IPNet, error) {
	var requestedSourcePrefixes []string
	allowedSources := make([]net.IPNet, 0)
	err := json.Unmarshal([]byte(value), &requestedSourcePrefixes)
	if err != nil {
		return nil, errors.Errorf("failed to parse '%s' as JSON: %s", value, err)
	}
	for _, prefix := range requestedSourcePrefixes {
		_, ipn, err := cnet.ParseCIDROrIP(prefix)
		if err != nil {
			return nil, errors.Wrapf(err, "Could not parse %s", prefix)
		}
		allowedSources = append(allowedSources, ipn.Network().IPNet)
	}
	return allowedSources, nil
}

func parsePodAnnotations(podSpec *LocalPodSpec, annotations map[string]string) (err error) {
	for key, value := range annotations {
		switch key {
		case config.CalicoAnnotationPrefix + config.SpoofAnnotation:
			podSpec.AllowedSpoofingSources, err = parseSpoofAddressAnnotation(value)
			if err != nil {
				return errors.Wrapf(err, "error parsing allowSpoofing addresses")
			}
		case config.VppAnnotationPrefix + config.IfSpecAnnotation:
			var ifSpecs map[string]config.InterfaceSpec
			err = json.Unmarshal([]byte(value), &ifSpecs)
			if err != nil {
				return fmt.Errorf("Error parsing key %s %s", key, err)
			}
			for _, ifSpec := range ifSpecs {
				if err := ifSpec.Validate(config.GetCalicoVppInterfaces().MaxPodIfSpec); err != nil {
					return errors.Wrap(err, "Pod interface config exceeds max config")
				}
			}
			if ethSpec, found := ifSpecs[podSpec.InterfaceName]; found {
				podSpec.IfSpec = ethSpec
				isL3 := podSpec.IfSpec.GetIsL3(isMemif(podSpec.InterfaceName))
				podSpec.IfSpec.IsL3 = &isL3
			}

		case config.VppAnnotationPrefix + config.MemifPortAnnotation:
			podSpec.EnableMemif = true
			err = parsePortMappingAnnotation(podSpec, VppIfTypeMemif, value)
			if err != nil {
				return err
			}
			err = parseDefaultIfType(podSpec, VppIfTypeTunTap)
			if err != nil {
				return errors.Wrapf(err, "Error parsing key %s", key)
			}
		case config.VppAnnotationPrefix + config.IfSpecPBLAnnotation:
			var ifSpec *config.InterfaceSpec
			err := json.Unmarshal([]byte(value), &ifSpec)
			if err != nil {
				return errors.Wrapf(err, "Error parsing key %s", key)
			}
			err = ifSpec.Validate(config.GetCalicoVppInterfaces().MaxPodIfSpec)
			if err != nil {
				return errors.Wrap(err, "PBL Memif interface config exceeds max config")
			}
			podSpec.PBLMemifSpec = *ifSpec
			isL3 := podSpec.PBLMemifSpec.GetIsL3(true)
			podSpec.PBLMemifSpec.IsL3 = &isL3
		case config.VppAnnotationPrefix + config.VclAnnotation:
			podSpec.EnableVCL, err = parseEnableDisableAnnotation(value)
			if err != nil {
				return errors.Wrapf(err, "Error parsing key %s", key)
			}
		default:
			continue
		}
	}
	return err
}
