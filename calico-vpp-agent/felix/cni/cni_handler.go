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

package cni

import (
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cache"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type CNIHandler struct {
	log   *logrus.Entry
	vpp   *vpplink.VppLink
	cache *cache.Cache

	podInterfaceMap map[string]model.LocalPodSpec

	memifDriver    *podinterface.MemifPodInterfaceDriver
	tuntapDriver   *podinterface.TunTapPodInterfaceDriver
	vclDriver      *podinterface.VclPodInterfaceDriver
	loopbackDriver *podinterface.LoopbackPodInterfaceDriver
}

// Serve runs the grpc server for the Calico CNI backend API
func NewCNIHandler(vpp *vpplink.VppLink, cache *cache.Cache, log *logrus.Entry) *CNIHandler {
	return &CNIHandler{
		vpp:             vpp,
		log:             log,
		cache:           cache,
		podInterfaceMap: make(map[string]model.LocalPodSpec),
		tuntapDriver:    podinterface.NewTunTapPodInterfaceDriver(vpp, cache, log),
		memifDriver:     podinterface.NewMemifPodInterfaceDriver(vpp, cache, log),
		vclDriver:       podinterface.NewVclPodInterfaceDriver(vpp, cache, log),
		loopbackDriver:  podinterface.NewLoopbackPodInterfaceDriver(vpp, cache, log),
	}
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tun-%d", idx)
}

func (s *CNIHandler) OnNetAddedOrUpdated(old, new *common.NetworkDefinition) {
	s.rescanState()
}

func (s *CNIHandler) OnNetDeleted(old *common.NetworkDefinition) {
	s.rescanState()
}

func (s *CNIHandler) OnPodAdd(evt *model.CniPodAddEvent) error {
	podSpec := evt.PodSpec

	if podSpec.NetworkName != "" {
		networkDefinition, ok := s.cache.NetworkDefinitions[podSpec.NetworkName]
		if !ok {
			err := fmt.Errorf("trying to create a pod in an unexisting network %s", podSpec.NetworkName)
			evt.Done <- &cniproto.AddReply{
				Successful:   false,
				ErrorMessage: err.Error(),
			}
			return err
		} else {
			_, route, err := net.ParseCIDR(networkDefinition.Range)
			if err == nil {
				podSpec.Routes = append(podSpec.Routes, *route)
			}
		}
	}
	if podSpec.NetnsName == "" {
		s.log.Debugf("no netns passed, skipping")
		evt.Done <- &cniproto.AddReply{
			Successful: true,
		}
		return nil
	}

	s.log.Infof("pod(add) spec=%s network=%s", podSpec.String(), podSpec.NetworkName)

	existingSpec, ok := s.podInterfaceMap[podSpec.Key()]
	if ok {
		s.log.Info("pod(add) found existing spec")
		podSpec = &existingSpec
	}

	swIfIndex, err := s.AddVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
		s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err)
		evt.Done <- &cniproto.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}
		return err
	}
	if len(config.GetCalicoVppInitialConfig().RedirectToHostRules) != 0 && podSpec.NetworkName == "" {
		err := s.AddRedirectToHostToInterface(podSpec.TunTapSwIfIndex)
		if err != nil {
			s.log.Errorf("AddRedirectToHostToInterface failed %s : %v", podSpec.String(), err)
			evt.Done <- &cniproto.AddReply{
				Successful:   false,
				ErrorMessage: err.Error(),
			}
			return err
		}
	}

	s.podInterfaceMap[podSpec.Key()] = *podSpec
	err = model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		config.CniServerStateFilename,
	)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
	s.log.Infof("pod(add) Done spec=%s", podSpec.String())
	// XXX: container MAC doesn't make sense with tun, we just pass back a constant one.
	// How does calico / k8s use it?
	// TODO: pass real mac for tap ?
	evt.Done <- &cniproto.AddReply{
		Successful:        true,
		HostInterfaceName: swIfIdxToIfName(swIfIndex),
		ContainerMac:      "02:00:00:00:00:00",
	}
	return nil
}

func (s *CNIHandler) rescanState() {
	if *config.GetCalicoVppFeatureGates().VCLEnabled {
		err := s.vclDriver.Init()
		if err != nil {
			/* it might already be enabled, do not return */
			s.log.Errorf("Error initializing VCL %v", err)
		}
	}

	cniServerState, err := model.LoadCniServerState(config.CniServerStateFilename)
	if err != nil {
		s.log.Errorf("Error getting pods from file %s, removing cache", err)
		err := os.Remove(config.CniServerStateFilename)
		if err != nil {
			s.log.Errorf("Could not remove %s, %s", config.CniServerStateFilename, err)
		}
		// if the cniServerState file is corrupted, we remove it and give up.
		return
	}

	s.log.Infof("RescanState: re-creating all interfaces")
	for _, podSpec := range cniServerState.PodSpecs {
		// we copy podSpec as a pointer to it will be sent over the event chan
		podSpecCopy := podSpec.Copy()
		_, err := s.AddVppInterface(&podSpecCopy, false /* doHostSideConf */)
		switch err.(type) {
		case PodNSNotFoundErr:
			s.log.Infof("Interface restore but netns missing %s", podSpecCopy.String())
		case nil:
			s.log.Infof("pod(re-add) podSpec=%s", podSpecCopy.String())
			s.podInterfaceMap[podSpec.Key()] = podSpecCopy
		default:
			s.log.Errorf("Interface add failed %s : %v", podSpecCopy.String(), err)
		}
		if len(config.GetCalicoVppInitialConfig().RedirectToHostRules) != 0 && podSpecCopy.NetworkName == "" {
			err := s.AddRedirectToHostToInterface(podSpecCopy.TunTapSwIfIndex)
			if err != nil {
				s.log.Error(err)
			}
		}
	}
	err = model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		config.CniServerStateFilename,
	)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
}

func (s *CNIHandler) DelRedirectToHostOnInterface(swIfIndex uint32) error {
	err := s.vpp.SetClassifyInputInterfaceTables(swIfIndex, s.cache.RedirectToHostClassifyTableIndex, types.InvalidTableID, types.InvalidTableID, false /*isAdd*/)
	if err != nil {
		return errors.Wrapf(err, "Error deleting classify input table from interface")
	} else {
		s.log.Infof("pod(del) delete input acl table %d from interface %d successfully", s.cache.RedirectToHostClassifyTableIndex, swIfIndex)
		return nil
	}
}

func (s *CNIHandler) AddRedirectToHostToInterface(swIfIndex uint32) error {
	s.log.Infof("Setting classify input acl table %d on interface %d", s.cache.RedirectToHostClassifyTableIndex, swIfIndex)
	err := s.vpp.SetClassifyInputInterfaceTables(swIfIndex, s.cache.RedirectToHostClassifyTableIndex, types.InvalidTableID, types.InvalidTableID, true)
	if err != nil {
		s.log.Warnf("Error setting classify input table: %s, retrying...", err)
		return errors.Errorf("could not set input acl table %d for interface %d", s.cache.RedirectToHostClassifyTableIndex, swIfIndex)
	} else {
		s.log.Infof("set input acl table %d for interface %d successfully", s.cache.RedirectToHostClassifyTableIndex, swIfIndex)
		return nil
	}
}

func (s *CNIHandler) OnPodDelete(evt *model.CniPodDelEvent) {
	s.log.Infof("pod(del) key=%s", evt.PodSpecKey)
	initialSpec, ok := s.podInterfaceMap[evt.PodSpecKey]
	if !ok {
		s.log.Warnf("Unknown pod to delete key=%s", evt.PodSpecKey)
	} else {
		s.log.Infof("pod(del) spec=%s", initialSpec.String())
		s.DelVppInterface(&initialSpec)
		s.log.Infof("pod(del) Done! spec=%s", initialSpec.String())
	}

	delete(s.podInterfaceMap, evt.PodSpecKey)
	err := model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		config.CniServerStateFilename,
	)
	if err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}

	evt.Done <- &cniproto.DelReply{Successful: true}
}

func (s *CNIHandler) OnFelixConfChanged(old, new *felixConfig.Config) {
	if new != nil {
		s.tuntapDriver.FelixConfigChanged(
			new,
			0, /* ipipEncapRefCountDelta */
			0, /* vxlanEncapRefCountDelta */
			s.podInterfaceMap,
		)
	}
}

func (s *CNIHandler) OnIpamConfChanged(old, new *proto.IPAMPool) {
	ipipEncapRefCountDelta := 0
	vxlanEncapRefCountDelta := 0
	if old != nil && calicov3.VXLANMode(old.VxlanMode) != calicov3.VXLANModeNever && calicov3.VXLANMode(old.VxlanMode) != "" {
		vxlanEncapRefCountDelta--
	}
	if old != nil && calicov3.IPIPMode(old.IpipMode) != calicov3.IPIPModeNever && calicov3.IPIPMode(old.IpipMode) != "" {
		ipipEncapRefCountDelta--
	}
	if new != nil && calicov3.VXLANMode(new.VxlanMode) != calicov3.VXLANModeNever && calicov3.VXLANMode(new.VxlanMode) != "" {
		vxlanEncapRefCountDelta++
	}
	if new != nil && calicov3.IPIPMode(new.IpipMode) != calicov3.IPIPModeNever && calicov3.IPIPMode(new.IpipMode) != "" {
		ipipEncapRefCountDelta++
	}

	for _, podSpec := range s.podInterfaceMap {
		for _, swIfIndex := range []uint32{podSpec.LoopbackSwIfIndex, podSpec.TunTapSwIfIndex, podSpec.MemifSwIfIndex} {
			if swIfIndex != vpplink.InvalidID {
				s.log.Infof("Enable/Disable interface[%d] SNAT", swIfIndex)
				for _, ipFamily := range vpplink.IPFamilies {
					err := s.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIP6, podSpec.NeedsSnat(s.cache, ipFamily.IsIP6))
					if err != nil {
						s.log.WithError(err).Errorf("Error enabling/disabling %s snat", ipFamily.Str)
					}
				}
			}
		}
	}
	s.tuntapDriver.FelixConfigChanged(nil /* felixConfig */, ipipEncapRefCountDelta, vxlanEncapRefCountDelta, s.podInterfaceMap)
}

func (s *CNIHandler) CNIHandlerInit() error {
	s.rescanState()
	return nil
}

// ForceAddingNetworkDefinition will add another NetworkDefinition to this CNI server.
// The usage is mainly for testing purposes.
func (s *CNIHandler) ForceAddingNetworkDefinition(networkDefinition *common.NetworkDefinition) {
	s.cache.NetworkDefinitions[networkDefinition.Name] = networkDefinition
}
