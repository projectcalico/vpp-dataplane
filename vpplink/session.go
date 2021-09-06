// Copyright (C) 2021 Cisco Systems Inc.
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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/session"
)

func (v *VppLink) enableDisableSessionLayer(isEnable bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &session.SessionEnableDisableReply{}
	request := &session.SessionEnableDisable{
		IsEnable: isEnable,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Enable/Disable session failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Enable/Disable session failed with retval %d", response.Retval)
	}
	return nil
}

func (v *VppLink) EnableSessionLayer() error {
	return v.enableDisableSessionLayer(true)
}

func (v *VppLink) DisableSessionLayer() error {
	return v.enableDisableSessionLayer(false)
}

func (v *VppLink) enableDisableSessionSAPILayer(isEnable bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &session.SessionEnableDisableReply{}
	request := &session.SessionEnableDisable{
		IsEnable: isEnable,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Enable/Disable session SAPI failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Enable/Disable session SAPI failed with retval %d", response.Retval)
	}
	return nil
}

func (v *VppLink) EnableSessionSAPI() error {
	return v.enableDisableSessionSAPILayer(true)
}

func (v *VppLink) DisableSessionSAPI() error {
	return v.enableDisableSessionSAPILayer(false)
}

func (v *VppLink) addDelSessionAppNamespace(namespaceId string, netns string, swIfIndex uint32, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &session.AppNamespaceAddDelV2Reply{}
	request := &session.AppNamespaceAddDelV2{
		SwIfIndex:   interface_types.InterfaceIndex(swIfIndex),
		NamespaceID: namespaceId,
		Netns:       netns,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Add/Del session namespace")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add/Del session namespace with retval %d", response.Retval)
	}
	return nil
}

func (v *VppLink) AddSessionAppNamespace(namespaceId string, netns string, swIfIndex uint32) error {
	return v.addDelSessionAppNamespace(namespaceId, netns, swIfIndex, true /* isAdd */)
}

func (v *VppLink) DelSessionAppNamespace(namespaceId string, netns string, swIfIndex uint32) error {
	return v.addDelSessionAppNamespace(namespaceId, netns, swIfIndex, false /* isAdd */)
}
