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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~215-g37bd1e445/feature"
)

func (v *VppLink) featureEnableDisable(swIfIndex uint32, isEnable bool, arcName, featureName string) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &feature.FeatureEnableDisableReply{}
	request := &feature.FeatureEnableDisable{
		SwIfIndex:   feature.InterfaceIndex(swIfIndex),
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

func (v *VppLink) EnableSNAT(swIfIndex uint32, isIp6 bool) (err error) {
	if isIp6 {
		return v.featureEnableDisable(swIfIndex, true, "ip6-unicast", "calico-snat")
	}
	return v.featureEnableDisable(swIfIndex, true, "ip4-unicast", "calico-snat")
}

func (v *VppLink) DisableSNAT(swIfIndex uint32, isIp6 bool) (err error) {
	if isIp6 {
		return v.featureEnableDisable(swIfIndex, false, "ip6-unicast", "calico-snat")
	}
	return v.featureEnableDisable(swIfIndex, false, "ip4-unicast", "calico-snat")
}
