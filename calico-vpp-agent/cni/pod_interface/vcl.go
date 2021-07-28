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
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

type VclPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func NewVclPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *VclPodInterfaceDriver {
	i := &VclPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.name = storage.VppVclName
	i.IfType = storage.VppVcl
	return i
}

func (i *VclPodInterfaceDriver) Create(podSpec *storage.LocalPodSpec, swIfIndex uint32) (err error) {
	vclTag := podSpec.GetInterfaceTag(i.name)
	// Clean up old tun if one is found with this tag
	// TODO : search namespace before creating

	err = i.vpp.EnableSessionLayer()
	if err != nil {
		return err
	}

	err = i.vpp.EnableSessionSAPI()
	if err != nil {
		return err
	}

	err = i.vpp.AddSessionAppNamespace(vclTag, podSpec.NetnsName, swIfIndex)
	if err != nil {
		return err
	}

	err = i.vpp.EnableFeatureArc46(swIfIndex, vpplink.FeatureArcHsi)
	if err != nil {
		return err
	}

	return nil
}

func (i *VclPodInterfaceDriver) Delete(podSpec *storage.LocalPodSpec) {
	// TODO
}
