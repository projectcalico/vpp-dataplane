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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/cnat"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	FeatureArcCnatInput  = "ip?-unicast cnat-input-ip?"
	FeatureArcCnatOutput = "ip?-output cnat-output-ip?"
	FeatureArcSnat       = "ip?-unicast cnat-snat-ip?"
)

const InvalidID = ^uint32(0)

func (v *VppLink) CnatPurge() error {
	client := cnat.NewServiceClient(v.GetConnection())

	_, err := client.CnatSessionPurge(v.GetContext(), &cnat.CnatSessionPurge{})
	if err != nil {
		return fmt.Errorf("cnat purge failed: %w", err)
	}
	return nil
}

func (v *VppLink) CnatTranslateAdd(tr *types.CnatTranslateEntry) (uint32, error) {
	if len(tr.Backends) == 0 {
		return InvalidID, nil
	}
	client := cnat.NewServiceClient(v.GetConnection())

	paths := make([]cnat.CnatEndpointTuple, 0, len(tr.Backends))
	for _, backend := range tr.Backends {
		paths = append(paths, cnat.CnatEndpointTuple{
			SrcEp: types.ToCnatEndpoint(backend.SrcEndpoint),
			DstEp: types.ToCnatEndpoint(backend.DstEndpoint),
			Flags: backend.Flags,
		})
	}

	response, err := client.CnatTranslationUpdate(v.GetContext(), &cnat.CnatTranslationUpdate{
		Translation: cnat.CnatTranslation{
			Vip:            types.ToCnatEndpoint(tr.Endpoint),
			IPProto:        types.ToVppIPProto(tr.Proto),
			Paths:          paths,
			IsRealIP:       BoolToU8(tr.IsRealIP),
			Flags:          uint8(cnat.CNAT_TRANSLATION_ALLOC_PORT | cnat.CNAT_TRANSLATION_NO_CLIENT),
			LbType:         cnat.CnatLbType(tr.LbType),
			FlowHashConfig: ip.IPFlowHashConfigV2(tr.HashConfig),
		},
	})
	if err != nil {
		return InvalidID, fmt.Errorf("add/upd CnatTranslate failed: %w", err)
	}
	return response.ID, nil
}

func (v *VppLink) CnatTranslateDel(id uint32) error {
	client := cnat.NewServiceClient(v.GetConnection())

	// corresponds to adding tr.Backends == []
	if id == InvalidID {
		return nil
	}

	_, err := client.CnatTranslationDel(v.GetContext(), &cnat.CnatTranslationDel{ID: id})
	if err != nil {
		return fmt.Errorf("deleting CnatTranslate failed: %w", err)
	}
	return nil
}

func (v *VppLink) CnatSetSnatAddresses(v4, v6 net.IP) error {
	client := cnat.NewServiceClient(v.GetConnection())

	_, err := client.CnatSetSnatAddresses(v.GetContext(), &cnat.CnatSetSnatAddresses{
		SnatIP4:   types.ToVppIP4Address(v4),
		SnatIP6:   types.ToVppIP6Address(v6),
		SwIfIndex: types.InvalidInterface,
		Flags:     cnat.CNAT_TRANSLATION_NO_CLIENT,
	})
	if err != nil {
		return fmt.Errorf("setting SNAT addresses failed: %w", err)
	}
	return nil
}

func (v *VppLink) CnatAddDelSnatPrefix(prefix *net.IPNet, isAdd bool) error {
	client := cnat.NewServiceClient(v.GetConnection())

	_, err := client.CnatSnatPolicyAddDelExcludePfx(v.GetContext(), &cnat.CnatSnatPolicyAddDelExcludePfx{
		IsAdd:  BoolToU8(isAdd),
		Prefix: types.ToVppPrefix(prefix),
	})
	if err != nil {
		return fmt.Errorf("%s SNAT prefix failed: %w", IsAddToStr(isAdd), err)
	}
	return nil
}

func (v *VppLink) CnatAddSnatPrefix(prefix *net.IPNet) error {
	return v.CnatAddDelSnatPrefix(prefix, true)
}

func (v *VppLink) CnatDelSnatPrefix(prefix *net.IPNet) error {
	return v.CnatAddDelSnatPrefix(prefix, false)
}

func (v *VppLink) CnatEnableFeatures(swIfIndex uint32) error {
	client := cnat.NewServiceClient(v.GetConnection())

	request := &cnat.FeatureCnatEnableDisable{
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		EnableDisable: true,
	}
	_, err := client.FeatureCnatEnableDisable(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("FeatureEnableDisable %+v failed: %w", request, err)
	}
	return nil
}

func (v *VppLink) CnatDisableFeatures(swIfIndex uint32) error {
	client := cnat.NewServiceClient(v.GetConnection())

	request := &cnat.FeatureCnatEnableDisable{
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		EnableDisable: false,
	}
	_, err := client.FeatureCnatEnableDisable(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("FeatureEnableDisable %+v failed: %w", request, err)
	}
	return nil
}

func (v *VppLink) cnatSnatPolicyAddDelPodInterface(swIfIndex uint32, isAdd bool, table cnat.CnatSnatPolicyTable) error {
	client := cnat.NewServiceClient(v.GetConnection())

	_, err := client.CnatSnatPolicyAddDelIf(v.GetContext(), &cnat.CnatSnatPolicyAddDelIf{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     BoolToU8(isAdd),
		Table:     table,
	})
	if err != nil {
		return fmt.Errorf("cnatSnatPolicyAddDelIf %+v failed: %w", swIfIndex, err)
	}
	return nil
}

func (v *VppLink) RegisterPodInterface(swIfIndex uint32) (err error) {
	return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, true /* isAdd */, cnat.CNAT_POLICY_POD)
}

func (v *VppLink) RemovePodInterface(swIfIndex uint32) (err error) {
	return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, false /* isAdd */, cnat.CNAT_POLICY_POD)
}

func (v *VppLink) RegisterHostInterface(swIfIndex uint32) (err error) {
	return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, true /* isAdd */, cnat.CNAT_POLICY_HOST)
}

func (v *VppLink) RemoveHostInterface(swIfIndex uint32) (err error) {
	return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, false /* isAdd */, cnat.CNAT_POLICY_HOST)
}

func (v *VppLink) EnableDisableCnatSNAT(swIfIndex uint32, isIP6 bool, isEnable bool) (err error) {
	if isEnable {
		return v.enableCnatSNAT(swIfIndex, isIP6)
	} else {
		return v.disableCnatSNAT(swIfIndex, isIP6)
	}
}

func (v *VppLink) enableCnatSNAT(swIfIndex uint32, isIP6 bool) (err error) {
	if isIP6 {
		return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, true /* isAdd */, cnat.CNAT_POLICY_INCLUDE_V6)
	}
	return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, true /* isAdd */, cnat.CNAT_POLICY_INCLUDE_V4)
}

func (v *VppLink) disableCnatSNAT(swIfIndex uint32, isIP6 bool) (err error) {
	if isIP6 {
		return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, false /* isAdd */, cnat.CNAT_POLICY_INCLUDE_V6)
	}
	return v.cnatSnatPolicyAddDelPodInterface(swIfIndex, false /* isAdd */, cnat.CNAT_POLICY_INCLUDE_V4)
}

func (v *VppLink) cnatSetSnatPolicyForDefaultVRF(pol cnat.CnatSnatPolicies) error {
	client := cnat.NewServiceClient(v.GetConnection())

	_, err := client.CnatSetSnatPolicy(v.GetContext(), &cnat.CnatSetSnatPolicy{
		Policy: pol,
	})
	if err != nil {
		return fmt.Errorf("cnatSetSnatPolicy %+v failed: %w", pol, err)
	}
	return nil
}

func (v *VppLink) SetK8sSnatPolicy() (err error) {
	return v.cnatSetSnatPolicyForDefaultVRF(cnat.CNAT_POLICY_K8S)
}

func (v *VppLink) ClearSnatPolicy() (err error) {
	return v.cnatSetSnatPolicyForDefaultVRF(cnat.CNAT_POLICY_NONE)
}

func (v *VppLink) EnableCnatSNATOnInterfaceVRF(swifindex uint32) (err error) {
	client := cnat.NewServiceClient(v.GetConnection())

	_, err = client.ApplyDefaultCnatSnat(v.GetContext(), &cnat.ApplyDefaultCnatSnat{
		SwIfIndex: interface_types.InterfaceIndex(swifindex),
	})
	if err != nil {
		return fmt.Errorf("ApplyDefaultCnatSnat for interface %d failed: %w", swifindex, err)
	}
	return nil

}
