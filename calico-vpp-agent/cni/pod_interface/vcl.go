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
	// "net"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

const (
	vclSocketName = "@vpp/session"
)

type VclPodInterfaceDriver struct {
	PodInterfaceDriverData
}

func NewVclPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry) *VclPodInterfaceDriver {
	i := &VclPodInterfaceDriver{}
	i.vpp = vpp
	i.log = log
	i.name = "vcl"
	return i
}

func (i *VclPodInterfaceDriver) CreateInterface(podSpec *storage.LocalPodSpec) (err error) {
	// vclTag := podSpec.GetInterfaceTag(i.name)
	// Clean up old tun if one is found with this tag
	// TODO : search namespace before creating

	err = i.vpp.EnableSessionLayer()
	if err != nil {
		return err
	}

	//FIXME
	// err = i.vpp.EnableSessionSAPI()
	// if err != nil {
	// 	return err
	// }

	err = i.vpp.AddSessionAppNamespace(vclSocketName, podSpec.NetnsName, podSpec.LoopbackSwIfIndex)
	if err != nil {
		return err
	}

	err = i.vpp.InterfaceAdminUp(podSpec.LoopbackSwIfIndex)
	if err != nil {
		return err
	}

	return nil
}

func (i *VclPodInterfaceDriver) DeleteInterface(podSpec *storage.LocalPodSpec) {
	// TODO
}