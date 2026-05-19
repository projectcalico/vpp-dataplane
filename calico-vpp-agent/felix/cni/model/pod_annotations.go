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

package model

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type PodAnnotations struct {
	// AllowedSpoofingSources is the list of prefixes from which the pod is allowed
	// to send traffic
	AllowedSpoofingSources []net.IPNet `json:"allowedSpoofingPrefixes"`
	// EnableVCL tells whether the pod asked for VCL
	EnableVCL bool `json:"enableVCL"`
	// EnableMemif tells whether the pod asked for memif
	EnableMemif bool `json:"enableMemif"`
	// IfSpec is the interface specification (rx queues, queue sizes,...)
	IfSpec config.InterfaceSpec `json:"ifSpec"`
	// PBLMemifSpec is the additional interface specification
	// (rx queues, queue sizes,...)
	PBLMemifSpec config.InterfaceSpec `json:"pblMemifSpec"`
	// IfPortConfigs specifies a 2-tuple based (port and protocol) set
	// of rules allowing to split traffic between two interfaces,
	// typically a memif and a tuntap
	IfPortConfigs []LocalIfPortConfigs `json:"ifPortConfigs"`
	// PortFilteredIfType is the interface type to which we will forward
	// traffic MATCHING the portConfigs
	PortFilteredIfType VppInterfaceType `json:"portFilteredIfType"`
	// DefaultIfType is the interface type to which we will traffic
	// not matching portConfigs
	DefaultIfType VppInterfaceType `json:"defaultIfType"`
}

func NewPodAnnotations(interfaceName string, annotations map[string]string) (*PodAnnotations, error) {
	var err error
	podAnnotations := &PodAnnotations{
		IfSpec:        getDefaultIfSpec(true /* isL3 */),
		PBLMemifSpec:  getDefaultIfSpec(false /* isL3 */),
		IfPortConfigs: make([]LocalIfPortConfigs, 0),
	}
	for key, value := range annotations {
		switch key {
		case config.SpoofAnnotation:
			podAnnotations.AllowedSpoofingSources, err = parseSpoofAddressAnnotation(value)
			if err != nil {
				return podAnnotations, errors.Wrapf(err, "error parsing allowSpoofing addresses")
			}
		case config.IfSpecAnnotation:
			var ifSpecs map[string]config.InterfaceSpec
			err = json.Unmarshal([]byte(value), &ifSpecs)
			if err != nil {
				return podAnnotations, fmt.Errorf("error parsing key %s %s", key, err)
			}
			for _, ifSpec := range ifSpecs {
				if err := ifSpec.Validate(config.GetCalicoVppInterfaces().MaxPodIfSpec); err != nil {
					return podAnnotations, errors.Wrap(err, "Pod interface config exceeds max config")
				}
			}
			if ethSpec, found := ifSpecs[interfaceName]; found {
				podAnnotations.IfSpec = ethSpec
				isL3 := podAnnotations.IfSpec.GetIsL3(isMemif(interfaceName))
				podAnnotations.IfSpec.IsL3 = &isL3
			}

		case config.MemifPortAnnotation:
			podAnnotations.EnableMemif = true
			err = parsePortMappingAnnotation(podAnnotations, VppIfTypeMemif, value)
			if err != nil {
				return podAnnotations, err
			}
			err = parseDefaultIfType(podAnnotations, VppIfTypeTunTap)
			if err != nil {
				return podAnnotations, errors.Wrapf(err, "Error parsing key %s", key)
			}
		case config.IfSpecPBLAnnotation:
			var ifSpec *config.InterfaceSpec
			err := json.Unmarshal([]byte(value), &ifSpec)
			if err != nil {
				return podAnnotations, errors.Wrapf(err, "Error parsing key %s", key)
			}
			err = ifSpec.Validate(config.GetCalicoVppInterfaces().MaxPodIfSpec)
			if err != nil {
				return podAnnotations, errors.Wrap(err, "PBL Memif interface config exceeds max config")
			}
			podAnnotations.PBLMemifSpec = *ifSpec
			isL3 := podAnnotations.PBLMemifSpec.GetIsL3(true)
			podAnnotations.PBLMemifSpec.IsL3 = &isL3
		case config.VclAnnotation:
			podAnnotations.EnableVCL, err = parseEnableDisableAnnotation(value)
			if err != nil {
				return podAnnotations, errors.Wrapf(err, "Error parsing key %s", key)
			}
		default:
			continue
		}
	}
	if podAnnotations.DefaultIfType == VppIfTypeUnknown {
		podAnnotations.DefaultIfType = VppIfTypeTunTap
	}

	return podAnnotations, err
}

type VppInterfaceType uint8

const (
	VppIfTypeUnknown VppInterfaceType = iota
	VppIfTypeTunTap
	VppIfTypeMemif
	VppIfTypeVCL
)

func (ift VppInterfaceType) String() string {
	switch ift {
	case VppIfTypeUnknown:
		return "Unknown"
	case VppIfTypeTunTap:
		return "TunTap"
	case VppIfTypeMemif:
		return "Memif"
	case VppIfTypeVCL:
		return "VCL"
	default:
		return "Unknown"
	}
}

func getDefaultIfSpec(isL3 bool) config.InterfaceSpec {
	return config.InterfaceSpec{
		NumRxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumRxQueues,
		NumTxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumTxQueues,
		RxQueueSize: vpplink.DefaultIntTo(
			config.GetCalicoVppInterfaces().DefaultPodIfSpec.RxQueueSize,
			vpplink.CalicoVppDefaultQueueSize,
		),
		TxQueueSize: vpplink.DefaultIntTo(
			config.GetCalicoVppInterfaces().DefaultPodIfSpec.TxQueueSize,
			vpplink.CalicoVppDefaultQueueSize,
		),
		IsL3: &isL3,
	}
}

func parsePortSpec(value string) (ifPortConfigs *LocalIfPortConfigs, err error) {
	ifPortConfigs = &LocalIfPortConfigs{}
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

func parsePortMappingAnnotation(podAnnotations *PodAnnotations, ifType VppInterfaceType, value string) (err error) {
	if podAnnotations.PortFilteredIfType != VppIfTypeUnknown && podAnnotations.PortFilteredIfType != ifType {
		return fmt.Errorf("cannot use port filters on different interface type")
	}
	podAnnotations.PortFilteredIfType = ifType
	// value is expected to be like "tcp:1234-1236,udp:4456"
	portSpecs := strings.Split(value, ",")
	for idx, portSpec := range portSpecs {
		ifPortConfig, err := parsePortSpec(portSpec)
		if err != nil {
			return errors.Wrapf(err, "Error parsing portSpec[%d] %s", idx, portSpec)
		}
		podAnnotations.IfPortConfigs = append(podAnnotations.IfPortConfigs, *ifPortConfig)
	}
	return nil
}

func parseDefaultIfType(podAnnotations *PodAnnotations, ifType VppInterfaceType) (err error) {
	if podAnnotations.DefaultIfType != VppIfTypeUnknown && podAnnotations.DefaultIfType != ifType {
		return fmt.Errorf("cannot set two different default interface type")
	}
	podAnnotations.DefaultIfType = ifType
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
