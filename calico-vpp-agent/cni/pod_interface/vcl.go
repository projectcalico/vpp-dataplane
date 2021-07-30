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
	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	// "github.com/projectcalico/vpp-dataplane/vpplink/types"
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

func (i *VclPodInterfaceDriver) Create(podSpec *storage.LocalPodSpec, tunTapSwIfIndex uint32) (err error) {
	vclTag := podSpec.GetInterfaceTag(i.name)
	// Clean up old tun if one is found with this tag
	// TODO : search namespace before creating

	err = i.vpp.EnableSessionLayer()
	if err != nil {
		return err
	}

	//FIXME
	err = i.vpp.EnableSessionSAPI()
	if err != nil {
		return err
	}

	swIfIndex, err := i.vpp.CreateLoopback(&config.ContainerSideMacAddress)
	if err != nil {
		return err
	}

	err = i.vpp.SetInterfaceVRF46(swIfIndex, podSpec.VrfId)
	if err != nil {
		return errors.Wrapf(err, "error setting loopback %d in per pod vrf", swIfIndex)
	}

	for _, containerIP := range podSpec.GetContainerIps() {
		err = i.vpp.AddInterfaceAddress(swIfIndex, containerIP)
		if err != nil {
			i.log.Errorf("Error adding address to pod loopback interface: %v", err)
		}

		// err := i.vpp.RouteAdd(&types.Route{
		// 	Dst: containerIP,
		// 	Paths: []types.RoutePath{{
		// 		Table: int(podSpec.VrfId),
		// 	}},
		// })
		// if err != nil {
		// 	return errors.Wrapf(err, "error adding vpp side routes for interface")
		// }

// FIXME :: 
// ip route add 11.0.166.130/32 via ip4-lookup-in-table 11
	}

	err = i.vpp.AddSessionAppNamespace(vclTag, podSpec.NetnsName, swIfIndex)
	if err != nil {
		return err
	}

	// TODO : not needed anymore ?
	// err = i.vpp.EnableFeatureArc46(tunTapSwIfIndex, vpplink.FeatureArcHsi)
	// if err != nil {
	// 	return err
	// }

	err = i.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return err
	}

	err = i.vpp.PuntRedirectTable(tunTapSwIfIndex, podSpec.VrfId, false)
	if err != nil {
		return errors.Wrapf(err, "Error configuring ipv4 punt")
	}
	err = i.vpp.PuntAllL4(false /*isip6*/)
	if err != nil {
		return errors.Wrapf(err, "Error configuring ipv4 L4 punt")
	}
	err = i.vpp.PuntRedirectTable(tunTapSwIfIndex, podSpec.VrfId, true)
	if err != nil {
		return errors.Wrapf(err, "Error configuring ipv6 punt")
	}
	err = i.vpp.PuntAllL4(true /*isip6*/)
	if err != nil {
		return errors.Wrapf(err, "Error configuring ipv6 L4 punt")
	}

	return nil
}

func (i *VclPodInterfaceDriver) Delete(podSpec *storage.LocalPodSpec) {
	// TODO
}
