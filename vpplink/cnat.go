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

package vpplink

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/cnat"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const InvalidID = ^uint32(0)

func (v *VppLink) CnatTranslateAdd(tr *types.CnatTranslateEntry) (id uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	if len(tr.Backends) == 0 {
		return InvalidID, nil
	}

	paths := make([]cnat.CnatEndpointTuple, 0, len(tr.Backends))
	for _, backend := range tr.Backends {
		paths = append(paths, cnat.CnatEndpointTuple{
			SrcEp: types.ToCnatEndpoint(backend.SrcEndpoint),
			DstEp: types.ToCnatEndpoint(backend.DstEndpoint),
		})
	}

	response := &cnat.CnatTranslationUpdateReply{}
	request := &cnat.CnatTranslationUpdate{
		Translation: cnat.CnatTranslation{
			Vip:      types.ToCnatEndpoint(tr.Endpoint),
			IPProto:  types.ToVppIPProto(tr.Proto),
			Paths:    paths,
			IsRealIP: BoolToU8(tr.IsRealIP),
			Flags:    uint8(cnat.CNAT_TRANSLATION_ALLOC_PORT),
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return InvalidID, errors.Wrap(err, "Add/Upd CnatTranslate failed")
	} else if response.Retval != 0 {
		return InvalidID, fmt.Errorf("Add/Upd CnatTranslate failed with retval: %d", response.Retval)
	}
	return response.ID, nil
}

func (v *VppLink) CnatTranslateDel(id uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &cnat.CnatTranslationDelReply{}
	request := &cnat.CnatTranslationDel{ID: id}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Deleting CnatTranslate failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Deleting CnatTranslate failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) CnatSetSnatAddresses(v4, v6 net.IP) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &cnat.CnatSetSnatAddresses{
		SnatIP4:   types.ToVppIP4Address(v4),
		SnatIP6:   types.ToVppIP6Address(v6),
		SwIfIndex: types.InvalidInterface,
	}
	response := &cnat.CnatSetSnatAddressesReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Setting SNAT addresses failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Setting SNAT addresses failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) CnatAddDelSnatPrefix(prefix *net.IPNet, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &cnat.CnatAddDelSnatPrefix{
		IsAdd:  BoolToU8(isAdd),
		Prefix: types.ToVppPrefix(prefix),
	}
	response := &cnat.CnatAddDelSnatPrefixReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Add/Del SNAT prefix failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add/Del SNAT prefix failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) CnatAddSnatPrefix(prefix *net.IPNet) error {
	return v.CnatAddDelSnatPrefix(prefix, true)
}

func (v *VppLink) CnatDelSnatPrefix(prefix *net.IPNet) error {
	return v.CnatAddDelSnatPrefix(prefix, false)
}

func (v *VppLink) CnatEnableFeatures(swIfIndex uint32) (err error) {
	err = v.EnableFeature(swIfIndex, "ip4-unicast", "cnat-input-ip4")
	if err != nil {
		return errors.Wrap(err, "Error enabling ip4 dnat in")
	}
	err = v.EnableFeature(swIfIndex, "ip4-output", "cnat-output-ip4")
	if err != nil {
		return errors.Wrap(err, "Error enabling ip4 dnat out")
	}
	err = v.EnableFeature(swIfIndex, "ip6-unicast", "cnat-input-ip6")
	if err != nil {
		return errors.Wrap(err, "Error enabling ip6 dnat in")
	}
	err = v.EnableFeature(swIfIndex, "ip6-output", "cnat-output-ip6")
	if err != nil {
		return errors.Wrap(err, "Error enabling ip6 dnat out")
	}
	return nil
}

func (v *VppLink) cnatK8sEnableDisableSNAT(swIfIndex uint32, isEnable bool, isIP6 bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &cnat.CnatK8sEnableDisableInterfaceSnatReply{}
	request := &cnat.CnatK8sEnableDisableInterfaceSnat{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIP6:     isIP6,
		IsEnable:  isEnable,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CnatK8sEnableDisableInterfaceSnat failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CnatK8sEnableDisableInterfaceSnat failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) EnableCnatK8sSNAT(swIfIndex uint32, isIp6 bool) (err error) {
	return v.cnatK8sEnableDisableSNAT(swIfIndex, true, isIp6)
}

func (v *VppLink) DisableCnatK8sSNAT(swIfIndex uint32, isIp6 bool) (err error) {
	return v.cnatK8sEnableDisableSNAT(swIfIndex, false, isIp6)
}

func (v *VppLink) cnatK8sAddDelPodInterface(swIfIndex uint32, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &cnat.CnatK8sRegisterPodInterfaceReply{}
	request := &cnat.CnatK8sRegisterPodInterface{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     isAdd,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CnatK8sRegisterPodInterface failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CnatK8sRegisterPodInterface failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) RegisterPodInterface(swIfIndex uint32) (err error) {
	return v.cnatK8sAddDelPodInterface(swIfIndex, true)
}

func (v *VppLink) RemovePodInterface(swIfIndex uint32) (err error) {
	return v.cnatK8sAddDelPodInterface(swIfIndex, false)
}

func (v *VppLink) CnatK8sAddDelPodCIDR(prefix *net.IPNet, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &cnat.CnatK8sAddDelPodCidrReply{}
	request := &cnat.CnatK8sAddDelPodCidr{
		Prefix: types.ToVppPrefix(prefix),
		IsAdd:  isAdd,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CnatK8sAddDelPodCidr failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CnatK8sAddDelPodCidr failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) AddPodCIDR(prefix *net.IPNet) (err error) {
	return v.CnatK8sAddDelPodCIDR(prefix, true)
}

func (v *VppLink) DelPodCIDR(prefix *net.IPNet) (err error) {
	return v.CnatK8sAddDelPodCIDR(prefix, false)
}

func (v *VppLink) cnatSetSnatPolicy(pol cnat.CnatSnatPolicies) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &cnat.CnatSetSnatPolicyReply{}
	request := &cnat.CnatSetSnatPolicy{
		Policy: pol,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CnatSetSnatPolicy failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CnatSetSnatPolicy failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) SetK8sSnatPolicy() (err error) {
	return v.cnatSetSnatPolicy(cnat.CNAT_SNAT_POLICY_K8S)
}

func (v *VppLink) ClearSnatPolicy() (err error) {
	return v.cnatSetSnatPolicy(cnat.CNAT_SNAT_POLICY_NONE)
}
