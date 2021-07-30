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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip"
)

func (v *VppLink) AddVRF(index uint32, isIP6 bool, name string) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &ip.IPTableAddDelReply{}
	request := &ip.IPTableAddDel{
		IsAdd: true,
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

func (v *VppLink) AddVRF46(index uint32, name string) (err error) {
	err = v.AddVRF(index, false, fmt.Sprintf("%s-ip4", name))
	if err != nil {
		return err
	}
	err = v.AddVRF(index, true, fmt.Sprintf("%s-ip6", name))
	if err != nil {
		return err
	}
	return nil
}
