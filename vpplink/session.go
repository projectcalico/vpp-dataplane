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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/session"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) enableDisableSessionLayer(isEnable bool) error {
	client := session.NewServiceClient(v.GetConnection())

	_, err := client.SessionEnableDisable(v.GetContext(), &session.SessionEnableDisable{
		IsEnable: isEnable,
	})
	if err != nil {
		return fmt.Errorf("failed to %s session: %w", strEnableDisable[isEnable], err)
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
	client := session.NewServiceClient(v.GetConnection())

	_, err := client.SessionSapiEnableDisable(v.GetContext(), &session.SessionSapiEnableDisable{
		IsEnable: isEnable,
	})
	if err != nil {
		return fmt.Errorf("failed to %s SAPI session: %w", strEnableDisable[isEnable], err)
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
	client := session.NewServiceClient(v.GetConnection())

	_, err := client.AppNamespaceAddDelV3(v.GetContext(), &session.AppNamespaceAddDelV3{
		Secret:      namespace.Secret,
		NamespaceID: namespace.NamespaceId,
		Netns:       namespace.Netns,
		SockName:    namespace.SocketName,
		SwIfIndex:   interface_types.InterfaceIndex(namespace.SwIfIndex),
		IsAdd:       isAdd,
	})
	if err != nil {
		return fmt.Errorf("failed to %s session namespace: %w", strAddRemove[isAdd], err)
	}
	return nil
}

func (v *VppLink) AddSessionAppNamespace(namespace *types.SessionAppNamespace) error {
	return v.addDelSessionAppNamespace(namespace, true /* isAdd */)
}

func (v *VppLink) DelSessionAppNamespace(namespace *types.SessionAppNamespace) error {
	return v.addDelSessionAppNamespace(namespace, false /* isAdd */)
}
