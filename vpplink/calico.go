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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~215-g37bd1e445/calico"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const InvalidID = ^uint32(0)

func (v *VppLink) CalicoTranslateAdd(tr *types.CalicoTranslateEntry) (id uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	if len(tr.Backends) == 0 {
		return InvalidID, nil
	}

	paths := make([]calico.CalicoEndpointTuple, 0, len(tr.Backends))
	for _, backend := range tr.Backends {
		paths = append(paths, calico.CalicoEndpointTuple{
			SrcEp: types.ToCalicoEndpoint(backend.SrcEndpoint),
			DstEp: types.ToCalicoEndpoint(backend.DstEndpoint),
		})
	}

	response := &calico.CalicoTranslationUpdateReply{}
	request := &calico.CalicoTranslationUpdate{
		Translation: calico.CalicoTranslation{
			Vip:      types.ToCalicoEndpoint(tr.Endpoint),
			IPProto:  types.ToCalicoProto(tr.Proto),
			Paths:    paths,
			IsRealIP: BoolToU8(tr.IsRealIP),
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return InvalidID, errors.Wrap(err, "Add/Upd CalicoTranslate failed")
	} else if response.Retval != 0 {
		return InvalidID, fmt.Errorf("Add/Upd CalicoTranslate failed with retval: %d", response.Retval)
	}
	return response.ID, nil
}

func (v *VppLink) CalicoTranslateDel(id uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &calico.CalicoTranslationDelReply{}
	request := &calico.CalicoTranslationDel{ID: id}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Deleting CalicoTranslate failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Deleting CalicoTranslate failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) CalicoSetSnatAddresses(v4, v6 net.IP) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &calico.CalicoSetSnatAddresses{
		SnatIP4: types.ToVppCalicoIp4Address(v4),
		SnatIP6: types.ToVppCalicoIp6Address(v6),
	}
	response := &calico.CalicoSetSnatAddressesReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Setting SNAT addresses failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Setting SNAT addresses failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) CalicoAddDelSnatPrefix(prefix *net.IPNet, isAdd bool) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &calico.CalicoAddDelSnatPrefix{
	  IsAdd: BoolToU8(isAdd),
	  Prefix: types.ToVppCalicoPrefix(prefix),
	}
	response := &calico.CalicoSetSnatAddressesReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Add/Del SNAT prefix failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add/Del SNAT prefix failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) CalicoAddSnatPrefix(prefix *net.IPNet) error {
	return v.CalicoAddDelSnatPrefix(prefix, true)
}

func (v *VppLink) CalicoDelSnatPrefix(prefix *net.IPNet) error {
	return v.CalicoAddDelSnatPrefix(prefix, false)
}

