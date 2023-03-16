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
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/session"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
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

	response := &session.SessionSapiEnableDisableReply{}
	request := &session.SessionSapiEnableDisable{
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

func (v *VppLink) addDelSessionAppNamespace(namespace *types.SessionAppNamespace, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &session.AppNamespaceAddDelV3Reply{}
	request := &session.AppNamespaceAddDelV3{
		Secret:      namespace.Secret,
		NamespaceID: namespace.NamespaceId,
		Netns:       namespace.Netns,
		SockName:    namespace.SocketName,
		SwIfIndex:   interface_types.InterfaceIndex(namespace.SwIfIndex),
		IsAdd:       isAdd,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "error %sing session namespace", IsAddToStr(isAdd))
	} else if response.Retval != 0 {
		return fmt.Errorf("%s session namespace errored with retval %d", IsAddToStr(isAdd), response.Retval)
	}
	return nil
}

func (v *VppLink) AddSessionAppNamespace(namespace *types.SessionAppNamespace) error {
	return v.addDelSessionAppNamespace(namespace, true /* isAdd */)
}

func (v *VppLink) DelSessionAppNamespace(namespace *types.SessionAppNamespace) error {
	return v.addDelSessionAppNamespace(namespace, false /* isAdd */)
}
