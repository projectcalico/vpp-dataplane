// Copyright (C) 2022 Cisco Systems Inc.
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
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/urpf"
)

func (v *VppLink) SetCustomURPF(swifindex uint32, tableId uint32) (err error) {
	response := &urpf.UrpfUpdateV2Reply{}
	request := &urpf.UrpfUpdateV2{
		Mode:      urpf.URPF_API_MODE_CUSTOM_VRF,
		SwIfIndex: interface_types.InterfaceIndex(swifindex),
		Af:        ip_types.ADDRESS_IP4,
		IsInput:   true,
		TableID:   tableId,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "setCustomURPF failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("setCustomURPF failed: req %+v reply %+v", request, response)
	}
	return
}

func (v *VppLink) UnsetURPF(swifindex uint32) (err error) {
	response := &urpf.UrpfUpdateV2Reply{}
	request := &urpf.UrpfUpdateV2{
		Mode:      urpf.URPF_API_MODE_OFF,
		SwIfIndex: interface_types.InterfaceIndex(swifindex),
		Af:        ip_types.ADDRESS_IP4,
		IsInput:   true,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "setOffURPF failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("setOffURPF failed: req %+v reply %+v", request, response)
	}
	return
}
