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

package vppmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	calicoopts "github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink/types"
)

func (v *VppRunner) doVppGlobalConfiguration() (err error) {
	vpp, err := config.CreateVppLink(v.log)
	v.vpp = vpp
	if err != nil {
		return errors.Wrap(err, "error connecting to VPP")
	}

	// Create all VRFs with a static ID that we use first so that we can
	// then call AllocateVRF without risk of conflict
	for _, ipFamily := range vpplink.IPFamilies {
		err := v.vpp.AddVRF(config.PuntTableID, ipFamily.IsIP6, fmt.Sprintf("punt-table-%s", ipFamily.Str))
		if err != nil {
			return errors.Wrapf(err, "Error creating punt vrf %s", ipFamily.Str)
		}
		err = v.vpp.AddVRF(config.PodVRFIndex, ipFamily.IsIP6, fmt.Sprintf("calico-pods-%s", ipFamily.Str))
		if err != nil {
			return err
		}
		err = v.vpp.AddDefaultRouteViaTable(config.PodVRFIndex, config.DefaultVRFIndex, ipFamily.IsIP6)
		if err != nil {
			return err
		}
	}

	err = v.vpp.ConfigureNeighborsV4(&types.NeighborConfig{
		MaxNumber: *config.GetCalicoVppInitialConfig().IP4NeighborsMaxNumber,
		MaxAge:    *config.GetCalicoVppInitialConfig().IP4NeighborsMaxAge,
	})
	if err != nil {
		return errors.Wrap(err, "error configuring v4 ip neighbors")
	}

	err = v.vpp.ConfigureNeighborsV6(&types.NeighborConfig{
		MaxNumber: *config.GetCalicoVppInitialConfig().IP6NeighborsMaxNumber,
		MaxAge:    *config.GetCalicoVppInitialConfig().IP6NeighborsMaxAge,
	})
	if err != nil {
		return errors.Wrap(err, "error configuring v6 ip neighbors")
	}

	for _, ipFamily := range vpplink.IPFamilies {
		err = v.vpp.PuntRedirect(types.IPPuntRedirect{
			RxSwIfIndex: vpplink.InvalidID,
			Paths: []types.RoutePath{{
				Table:     config.PuntTableID,
				SwIfIndex: types.InvalidID,
			}},
		}, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring punt redirect")
		}

		err = v.vpp.SetPuntL4(types.TCP, vpplink.PuntAllPorts, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring L4 TCP punt")
		}
		err = v.vpp.SetPuntL4(types.UDP, vpplink.PuntAllPorts, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "Error configuring L4 UDP punt")
		}
	}

	// We do not want NA we receive to be punted, as there is
	// no reason for us to forward them to pods, or to forward
	// them to the host as we have a ND proxy in place.
	puntReasonID, err := v.vpp.PuntReasonGet(vpplink.PuntReasonNeighAdv)
	if err != nil {
		return errors.Wrapf(err, "Could not get punt reason %s", vpplink.PuntReasonNeighAdv)
	}
	err = v.vpp.UnsetPuntException(puntReasonID)
	if err != nil {
		return errors.Wrapf(err, "Could not UnsetPuntException %d", puntReasonID)
	}

	return nil
}

func (v *VppRunner) updateCalicoNode(ifState *config.LinuxInterfaceState) (err error) {
	var node, updated *internalapi.Node
	var client calicov3cli.Interface

	if v.params.DisableUpdateCalicoNode {
		return nil
	}

	// TODO create if doesn't exist? need to be careful to do it atomically... and everyone else must as well.
	for i := 0; i < 10; i++ {
		client, err = calicov3cli.NewFromEnv()
		if err != nil {
			return errors.Wrap(err, "Error creating calico client")
		}
		ctx, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel1()
		node, err = client.Nodes().Get(ctx, *config.NodeName, calicoopts.GetOptions{})
		if err != nil {
			v.log.Warnf("Try [%d/10] cannot get current node from Calico %+v", i, err)
			time.Sleep(1 * time.Second)
			continue
		}
		// Update node with address
		needUpdate := false
		if node.Spec.BGP == nil {
			node.Spec.BGP = &internalapi.NodeBGPSpec{}
		}
		if ifState.GetNodeIP(vpplink.IPFamilyV4) != nil {
			v.log.Infof("Setting BGP nodeIP %s", ifState.GetNodeIP(vpplink.IPFamilyV4))
			if node.Spec.BGP.IPv4Address != ifState.GetNodeIP(vpplink.IPFamilyV4).String() {
				node.Spec.BGP.IPv4Address = ifState.GetNodeIP(vpplink.IPFamilyV4).String()
				needUpdate = true
			}
		} else {
			node.Spec.BGP.IPv4Address = ""
			needUpdate = true
		}
		if ifState.GetNodeIP(vpplink.IPFamilyV6) != nil {
			v.log.Infof("Setting BGP nodeIP %s", ifState.GetNodeIP(vpplink.IPFamilyV6))
			if node.Spec.BGP.IPv6Address != ifState.GetNodeIP(vpplink.IPFamilyV6).String() {
				node.Spec.BGP.IPv6Address = ifState.GetNodeIP(vpplink.IPFamilyV6).String()
				needUpdate = true
			}
		} else {
			node.Spec.BGP.IPv6Address = ""
			needUpdate = true
		}
		if needUpdate {
			v.log.Infof("Updating node, version = %s, metaversion = %s", node.ResourceVersion, node.ResourceVersion)
			v.log.Debugf("updating node with: %+v", node)
			ctx, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel2()
			updated, err = client.Nodes().Update(ctx, node, calicoopts.SetOptions{})
			if err != nil {
				v.log.Warnf("Try [%d/10] cannot update current node: %+v", i, err)
				time.Sleep(1 * time.Second)
				continue
			}
			v.log.Debugf("Updated node: %+v", updated)
			return nil
		} else {
			v.log.Infof("Node doesn't need updating :)")
			return nil
		}
	}
	return errors.Wrap(err, "Error updating node")
}
