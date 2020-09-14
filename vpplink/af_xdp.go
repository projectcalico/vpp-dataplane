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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/af_xdp"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) CreateAfXDP(intf *types.VppXDPInterface) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &af_xdp.AfXdpCreateReply{}
	request := &af_xdp.AfXdpCreate{
		HostIf:  intf.HostInterfaceName,
		Name:    intf.Name,
		RxqNum:  uint16(defaultIntTo(intf.NumRxQueues, 1)),
		RxqSize: uint16(defaultIntTo(intf.RxQueueSize, 1024)),
		TxqSize: uint16(defaultIntTo(intf.TxQueueSize, 1024)),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "CreateAfXDP failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("CreateAfXDP failed: req %+v reply %+v", request, response)
	}
	intf.SwIfIndex = uint32(response.SwIfIndex)
	return nil
}

func (v *VppLink) DeleteAfXDP(intf *types.VppXDPInterface) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &af_xdp.AfXdpDeleteReply{}
	request := &af_xdp.AfXdpDelete{
		SwIfIndex: interface_types.InterfaceIndex(intf.SwIfIndex),
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "DeleteAfXDP failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("DeleteAfXDP failed: req %+v reply %+v", request, response)
	}
	return nil
}
