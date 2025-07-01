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

package podinterface

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type VclPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func getPodAppNamespaceName(podSpec *model.LocalPodSpec) string {
	podSpecKey := model.LocalPodSpecKey(podSpec.NetnsName, podSpec.InterfaceName)
	return fmt.Sprintf("app-ns-%s", podSpecKey)
}

func NewVclPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *VclPodInterfaceDriver {
	i := &VclPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.Name = "vcl"
	return i
}

func (i *VclPodInterfaceDriver) Init() (err error) {
	/* Enable SAPI before session as enabling session
	 * will create default namespace */
	err = i.vpp.EnableSessionSAPI()
	if err != nil {
		return err
	}

	err = i.vpp.EnableSessionLayer()
	if err != nil {
		return err
	}

	return nil
}

func (i *VclPodInterfaceDriver) CreateInterface(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack) (err error) {
	appNamespace := &types.SessionAppNamespace{
		NamespaceID: getPodAppNamespaceName(podSpec),
		SwIfIndex:   podSpec.LoopbackSwIfIndex,
		SocketName:  fmt.Sprintf("abstract:%s,netns_name=%s", "vpp/session", podSpec.NetnsName),
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

func (i *VclPodInterfaceDriver) DeleteInterface(podSpec *model.LocalPodSpec) {
	var err error
	appNamespace := &types.SessionAppNamespace{
		NamespaceID: getPodAppNamespaceName(podSpec),
	}
	err = i.vpp.DelSessionAppNamespace(appNamespace)
	if err != nil {
		i.log.Errorf("Error deleting app ns %s", err)
	}
}
