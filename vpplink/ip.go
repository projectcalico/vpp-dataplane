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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/ip"
	vppip "github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/ip"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/punt"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) ListVRFs() (vrfs []types.VRF, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	vrfs = make([]types.VRF, 0)
	request := &vppip.IPTableDump{}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &vppip.IPTableDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return vrfs, errors.Wrap(err, "error listing VRF")
		}
		if stop {
			return vrfs, nil
		}
		vrfs = append(vrfs, types.VRF{
			Name:  response.Table.Name,
			VrfID: response.Table.TableID,
			IsIP6: response.Table.IsIP6,
		})
	}

}

func (v *VppLink) addDelVRF(index uint32, name string, isIP6 bool, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &ip.IPTableAddDelReply{}
	request := &ip.IPTableAddDel{
		IsAdd: isAdd,
		Table: ip.IPTable{
			TableID: index,
			IsIP6:   isIP6,
			Name:    name,
		},
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "IPTableAddDel failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("IPTableAddDel failed (retval %d). Request: %+v", response.Retval, request)
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
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &ip.IPTableAllocateReply{}
	request := &ip.IPTableAllocate{
		Table: ip.IPTable{
			TableID: types.InvalidID,
			IsIP6:   isIP6,
			Name:    name,
		},
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return types.InvalidID, errors.Wrapf(err, "IPTableAllocate failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return types.InvalidID, fmt.Errorf("IPTableAllocate failed (retval %d). Request: %+v", response.Retval, request)
	}
	return response.Table.TableID, nil
}

func (v *VppLink) PuntRedirect(punt types.IpPuntRedirect, isIP6 bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &vppip.AddDelIPPuntRedirectV2{
		Punt: vppip.PuntRedirectV2{
			RxSwIfIndex: interface_types.InterfaceIndex(punt.RxSwIfIndex),
			Af:          types.GetBoolIPFamily(isIP6),
			Paths:       types.ToFibPathList(punt.Paths, isIP6),
		},
		IsAdd: true,
	}
	response := &vppip.AddDelIPPuntRedirectV2Reply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set punt in VPP: %v %d", err, response.Retval)
	}
	return nil
}

func (v *VppLink) PuntRedirectList(swIfIndex uint32, isIP6 bool) (punts []types.IpPuntRedirect, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &ip.IPPuntRedirectV2Dump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Af:        types.GetBoolIPFamily(isIP6),
	}
	stream := v.ch.SendMultiRequest(request)
	punts = make([]types.IpPuntRedirect, 0)
	for {
		response := &ip.IPPuntRedirectV2Details{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return punts, err
		}
		if stop {
			break
		}
		punts = append(punts, types.IpPuntRedirect{
			RxSwIfIndex: uint32(response.Punt.RxSwIfIndex),
			IsIP6:       response.Punt.Af == ip_types.ADDRESS_IP6,
			Paths:       types.FromFibPathList(response.Punt.Paths),
		})
	}
	return punts, nil
}

// PuntL4 configures L4 punt for a given address family and protocol. port = ~0 means all ports
func (v *VppLink) PuntL4(proto types.IPProto, port uint16, isIPv6 bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	request := &punt.SetPunt{
		Punt: punt.Punt{
			Type: punt.PUNT_API_TYPE_L4,
			Punt: punt.PuntUnionL4(punt.PuntL4{
				Af:       types.ToVppAddressFamily(isIPv6),
				Protocol: types.ToVppIPProto(proto),
				Port:     port,
			}),
		},
		IsAdd: true,
	}
	response := &punt.SetPuntReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set punt in VPP: %v %d", err, response.Retval)
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
