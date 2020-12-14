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
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/calico"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) calicoEnableDisableSNAT(swIfIndex uint32, isEnable bool, isIP6 bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &calico.CalicoEnableDisableInterfaceSnatReply{}
	request := &calico.CalicoEnableDisableInterfaceSnat{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIP6:     isIP6,
		IsEnable:  isEnable,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CalicoEnableDisableInterfaceSnat failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CalicoEnableDisableInterfaceSnat failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) EnableCalicoSNAT(swIfIndex uint32, isIp6 bool) (err error) {
	return v.calicoEnableDisableSNAT(swIfIndex, true, isIp6)
}

func (v *VppLink) DisableCalicoSNAT(swIfIndex uint32, isIp6 bool) (err error) {
	return v.calicoEnableDisableSNAT(swIfIndex, false, isIp6)
}

func (v *VppLink) calicoAddDelPodInterface(swIfIndex uint32, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &calico.CalicoRegisterPodInterfaceReply{}
	request := &calico.CalicoRegisterPodInterface{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     isAdd,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CalicoRegisterPodInterface failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CalicoRegisterPodInterface failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) RegisterPodInterface(swIfIndex uint32) (err error) {
	return v.calicoAddDelPodInterface(swIfIndex, true)
}

func (v *VppLink) RemovePodInterface(swIfIndex uint32) (err error) {
	return v.calicoAddDelPodInterface(swIfIndex, false)
}

func (v *VppLink) CalicoAddDelPodCIDR(prefix *net.IPNet, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &calico.CalicoAddDelPodCidrReply{}
	request := &calico.CalicoAddDelPodCidr{
		Prefix: types.ToVppPrefix(prefix),
		IsAdd:  isAdd,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CalicoAddDelPodCidr failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CalicoAddDelPodCidr failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) AddPodCIDR(prefix *net.IPNet) (err error) {
	return v.CalicoAddDelPodCIDR(prefix, true)
}

func (v *VppLink) DelPodCIDR(prefix *net.IPNet) (err error) {
	return v.CalicoAddDelPodCIDR(prefix, false)
}
