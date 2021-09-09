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

package pod_interface

import (
	"fmt"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
)

const (
	vclSocketName = "@vpp/session"
)

type VclPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func getPodAppNamespaceName(podSpec *storage.LocalPodSpec) string {
	return fmt.Sprintf("app-ns-%s", podSpec.Key())
}

func NewVclPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *VclPodInterfaceDriver {
	i := &VclPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.name = "vcl"
	return i
}

func (i *VclPodInterfaceDriver) Init() (err error) {
	err = i.vpp.EnableSessionLayer()
	if err != nil {
		return err
	}

	err = i.vpp.EnableSessionSAPI()
	if err != nil {
		return err
	}
	return nil
}

func (i *VclPodInterfaceDriver) CreateInterface(podSpec *storage.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	appNamespace := &types.SessionAppNamespace{
		NamespaceId: getPodAppNamespaceName(podSpec),
		Netns:       podSpec.NetnsName,
		SwIfIndex:   podSpec.LoopbackSwIfIndex,
		SocketName:  vclSocketName,
		Secret:      0,
	}
	err = i.vpp.AddSessionAppNamespace(appNamespace)
	if err != nil {
		return err
	} else {
		stack.Push(i.vpp.DelSessionAppNamespace, appNamespace)
	}

	err = i.vpp.InterfaceAdminUp(podSpec.LoopbackSwIfIndex)
	if err != nil {
		return err
	}

	return nil
}

func (i *VclPodInterfaceDriver) DeleteInterface(podSpec *storage.LocalPodSpec) {
	var err error
	appNamespace := &types.SessionAppNamespace{
		NamespaceId: getPodAppNamespaceName(podSpec),
	}
	err = i.vpp.DelSessionAppNamespace(appNamespace)
	if err != nil {
		i.log.Errorf("Error deleting app ns %s", err)
	}
}
