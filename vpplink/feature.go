// Copyright (C) 2020 Cisco Systems Inc.
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

package vpplink

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/feature"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
)

const (
	FeatureArcCnatInput  = "ip?-unicast cnat-input-ip?"
	FeatureArcCnatOutput = "ip?-output cnat-output-ip?"
	FeatureArcSnat       = "ip?-unicast cnat-snat-ip?"
	FeatureArcHsi        = "ip?-output hsi-ip?"
)

func (v *VppLink) featureEnableDisable(swIfIndex uint32, isEnable bool, arcName, featureName string) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &feature.FeatureEnableDisableReply{}
	request := &feature.FeatureEnableDisable{
		SwIfIndex:   interface_types.InterfaceIndex(swIfIndex),
		Enable:      isEnable,
		ArcName:     arcName,
		FeatureName: featureName,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "FeatureEnableDisable failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("FeatureEnableDisable failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) EnableFeature(swIfIndex uint32, arcName, featureName string) (err error) {
	return v.featureEnableDisable(swIfIndex, true, arcName, featureName)
}

func (v *VppLink) DisableFeature(swIfIndex uint32, arcName, featureName string) (err error) {
	return v.featureEnableDisable(swIfIndex, false, arcName, featureName)
}

func parseArcDescription(arcDescription string, isIp6 bool) (arcName string, featureName string, err error) {
	parts := strings.Split(arcDescription, " ")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("wrong split len")
	}
	ipStr := "ip4"
	if isIp6 {
		ipStr = "ip6"
	}
	arcName = strings.ReplaceAll(parts[0], "ip?", ipStr)
	featureName = strings.ReplaceAll(parts[1], "ip?", ipStr)
	return arcName, featureName, nil
}

func (v *VppLink) enableDisableFeatureArc(swIfIndex uint32, arcDescription string, isIp6 bool, isEnable bool) (err error) {
	arcName, featureName, err := parseArcDescription(arcDescription, isIp6)
	if err != nil {
		return errors.Wrapf(err, "Error parsing arc description %s", arcDescription)
	}
	return v.featureEnableDisable(swIfIndex, isEnable, arcName, featureName)
}

func (v *VppLink) EnableFeatureArc46(swIfIndex uint32, arcDescription string) (err error) {
	err = v.enableDisableFeatureArc(swIfIndex, arcDescription, false /* isip6 */, true /* enable */)
	if err != nil {
		return errors.Wrapf(err, "Error enabling ip4 arc %s", arcDescription)
	}
	err = v.enableDisableFeatureArc(swIfIndex, arcDescription, true /* isip6 */, true /* enable */)
	if err != nil {
		return errors.Wrapf(err, "Error enabling ip6 arc %s", arcDescription)
	}
	return nil
}
