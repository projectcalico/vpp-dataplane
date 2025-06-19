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
	"io"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/punt"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) ListVRFs() (vrfs []types.VRF, err error) {
	client := ip.NewServiceClient(v.GetConnection())

	stream, err := client.IPTableDump(v.GetContext(), &ip.IPTableDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump VRF: %w", err)
	}
	vrfs = make([]types.VRF, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump VRF: %w", err)
		}
		vrfs = append(vrfs, types.VRF{
			Name:  response.Table.Name,
			VrfID: response.Table.TableID,
			IsIP6: response.Table.IsIP6,
		})
	}
	return vrfs, nil
}

func (v *VppLink) addDelVRF(index uint32, name string, isIP6 bool, isAdd bool) error {
	client := ip.NewServiceClient(v.GetConnection())

	_, err := client.IPTableAddDel(v.GetContext(), &ip.IPTableAddDel{
		IsAdd: isAdd,
		Table: ip.IPTable{
			TableID: index,
			IsIP6:   isIP6,
			Name:    name,
		},
	})
	if err != nil {
		return fmt.Errorf("ipTableAddDel failed: %w", err)
	}
	return nil
}

func (v *VppLink) AddVRF(index uint32, isIP6 bool, name string) error {
	return v.addDelVRF(index, name, isIP6, true /*isAdd*/)
}

func (v *VppLink) DelVRF(index uint32, isIP6 bool) error {
	return v.addDelVRF(index, "", isIP6, false /*isAdd*/)
}

func (v *VppLink) AllocateVRF(isIP6 bool, name string) (uint32, error) {
	client := ip.NewServiceClient(v.GetConnection())

	response, err := client.IPTableAllocate(v.GetContext(), &ip.IPTableAllocate{
		Table: ip.IPTable{
			TableID: types.InvalidID,
			IsIP6:   isIP6,
			Name:    name,
		},
	})
	if err != nil {
		return 0, fmt.Errorf("ipTableAllocate failed: %w", err)
	}
	return response.Table.TableID, nil
}

func (v *VppLink) PuntRedirect(punt types.IPPuntRedirect, isIP6 bool) error {
	client := ip.NewServiceClient(v.GetConnection())

	_, err := client.AddDelIPPuntRedirectV2(v.GetContext(), &ip.AddDelIPPuntRedirectV2{
		Punt: ip.PuntRedirectV2{
			RxSwIfIndex: interface_types.InterfaceIndex(punt.RxSwIfIndex),
			Af:          types.GetBoolIPFamily(isIP6),
			Paths:       types.ToFibPathList(punt.Paths, isIP6),
		},
		IsAdd: true,
	})
	if err != nil {
		return fmt.Errorf("failed to set punt in VPP: %v", err)
	}
	return nil
}

func (v *VppLink) PuntRedirectList(swIfIndex uint32, isIP6 bool) (punts []types.IPPuntRedirect, err error) {
	client := ip.NewServiceClient(v.GetConnection())

	stream, err := client.IPPuntRedirectV2Dump(v.GetContext(), &ip.IPPuntRedirectV2Dump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Af:        types.GetBoolIPFamily(isIP6),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump punt redirect: %w", err)
	}
	punts = make([]types.IPPuntRedirect, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump punt redirect: %w", err)
		}
		punts = append(punts, types.IPPuntRedirect{
			RxSwIfIndex: uint32(response.Punt.RxSwIfIndex),
			IsIP6:       response.Punt.Af == ip_types.ADDRESS_IP6,
			Paths:       types.FromFibPathList(response.Punt.Paths),
		})
	}
	return punts, nil
}

// PuntL4 configures L4 punt for a given address family and protocol. port = ~0 means all ports
func (v *VppLink) PuntL4(proto types.IPProto, port uint16, isIPv6 bool) error {
	client := punt.NewServiceClient(v.GetConnection())

	_, err := client.SetPunt(v.GetContext(), &punt.SetPunt{
		IsAdd: true,
		Punt: punt.Punt{
			Type: punt.PUNT_API_TYPE_L4,
			Punt: punt.PuntUnionL4(punt.PuntL4{
				Af:       types.ToVppAddressFamily(isIPv6),
				Protocol: types.ToVppIPProto(proto),
				Port:     port,
			}),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set punt in VPP: %v", err)
	}
	return nil
}

func (v *VppLink) PuntAllL4(isIPv6 bool) (err error) {
	err = v.PuntL4(types.TCP, 0xffff, isIPv6)
	if err != nil {
		return err
	}
	err = v.PuntL4(types.UDP, 0xffff, isIPv6)
	if err != nil {
		return err
	}
	return nil
}
