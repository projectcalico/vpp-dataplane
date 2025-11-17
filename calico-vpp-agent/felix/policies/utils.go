// Copyright (C) 2025 Cisco Systems Inc.
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

package policies

import (
	"github.com/pkg/errors"
	felixConfig "github.com/projectcalico/calico/felix/config"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

func protoPortListEqual(a, b []felixConfig.ProtoPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i, elemA := range a {
		elemB := b[i]
		if elemA.Net != elemB.Net {
			return false
		}
		if elemA.Protocol != elemB.Protocol {
			return false
		}
		if elemA.Port != elemB.Port {
			return false
		}
	}
	return true
}

type interfaceDetails struct {
	tapIndex    uint32
	uplinkIndex uint32
	addresses   []string
}

func mapTagToInterfaceDetails(vpp *vpplink.VppLink) (tagIfDetails map[string]interfaceDetails, err error) {
	tagIfDetails = make(map[string]interfaceDetails)
	uplinkSwifindexes, err := vpp.SearchInterfacesWithTagPrefix("main-")
	if err != nil {
		return nil, err
	}
	tapSwifindexes, err := vpp.SearchInterfacesWithTagPrefix("host-")
	if err != nil {
		return nil, err
	}
	for intf, uplink := range uplinkSwifindexes {
		tap, found := tapSwifindexes["host-"+intf[5:]]
		if found {
			ip4adds, err := vpp.AddrList(uplink, false)
			if err != nil {
				return nil, err
			}
			ip6adds, err := vpp.AddrList(uplink, true)
			if err != nil {
				return nil, err
			}
			adds := append(ip4adds, ip6adds...)
			addresses := []string{}
			for _, add := range adds {
				addresses = append(addresses, add.IPNet.IP.String())
			}
			tagIfDetails[intf[5:]] = interfaceDetails{tap, uplink, addresses}
		} else {
			return nil, errors.Errorf("uplink interface %d not corresponding to a tap interface", uplink)
		}
	}
	return tagIfDetails, nil
}
