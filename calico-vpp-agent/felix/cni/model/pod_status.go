// Copyright (C) 2025 Cisco Systems Inc.
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

package model

import (
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// LocalPodSpecStatus contains VPP internal ids, mutable fields in AddVppInterface
// We persist them on the disk to avoid rescanning when the agent is restarting.
//
// We should be careful during state-reconciliation as they might not be
// valid anymore. VRF tags should provide this guarantee
//
// These fields are only a runtime cache, but we also store them
// on the disk for debugging & graceful restart.
type LocalPodSpecStatus struct {
	// MemifSocketID is the socket ID of the memif in VPP for this pod
	MemifSocketID uint32 `json:"memifSocketId"`
	// MemifSwIfIndex is the sw_if_index the memif in VPP for this pod
	MemifSwIfIndex uint32 `json:"memifSwIfIndex"`
	// TunTapSwIfIndex is the sw_if_index the tuntap in VPP for this pod
	TunTapSwIfIndex uint32 `json:"tunTapSwIfIndex"`
	// LoopbackSwIfIndex is the sw_if_index the loopback in VPP for this pod
	LoopbackSwIfIndex uint32 `json:"loopbackSwIfIndex"`
	// PblIndexes is a map from containerIP to PBL index in VPP
	PblIndexes map[string]uint32 `json:"pblIndexes"`
	// HostPortEntryIDs is a map from hostport to corresponding cnat entry ids
	// in VPP, per hostIP (we can have both ipv4 and ipv6)
	HostPortEntryIDs map[uint16]map[string]uint32
	// V4VrfID is the table ID for the v4 VRF created for the pod
	V4VrfID uint32 `json:"v4VrfId"`
	// V4RPFVrfID is the table ID for the v4 uRPF VRF created for the pod
	V4RPFVrfID uint32 `json:"v4RPFVrfId"`
	// V6VrfID is the table ID for the v6 VRF created for the pod
	V6VrfID uint32 `json:"v6VrfId"`
	// V6RPFVrfID is the table ID for the v6 uRPF VRF created for the pod
	V6RPFVrfID uint32 `json:"v6RPFVrfId"`
}

func NewLocalPodSpecStatus() *LocalPodSpecStatus {
	return &LocalPodSpecStatus{
		MemifSocketID:     vpplink.InvalidID,
		MemifSwIfIndex:    vpplink.InvalidID,
		TunTapSwIfIndex:   vpplink.InvalidID,
		LoopbackSwIfIndex: vpplink.InvalidID,
		PblIndexes:        make(map[string]uint32),
		HostPortEntryIDs:  make(map[uint16]map[string]uint32),
		V4VrfID:           vpplink.InvalidID,
		V4RPFVrfID:        vpplink.InvalidID,
		V6VrfID:           vpplink.InvalidID,
		V6RPFVrfID:        vpplink.InvalidID,
	}
}

func (podSpecStatus *LocalPodSpecStatus) GetVrfID(ipFamily vpplink.IPFamily) uint32 {
	if ipFamily.IsIP6 {
		return podSpecStatus.V6VrfID
	} else {
		return podSpecStatus.V4VrfID
	}
}

func (podSpecStatus *LocalPodSpecStatus) GetRPFVrfID(ipFamily vpplink.IPFamily) uint32 {
	if ipFamily.IsIP6 {
		return podSpecStatus.V6RPFVrfID
	} else {
		return podSpecStatus.V4RPFVrfID
	}
}

func (podSpecStatus *LocalPodSpecStatus) SetVrfID(id uint32, ipFamily vpplink.IPFamily) {
	if ipFamily.IsIP6 {
		podSpecStatus.V6VrfID = id
	} else {
		podSpecStatus.V4VrfID = id
	}
}

func (podSpecStatus *LocalPodSpecStatus) SetRPFVrfID(id uint32, ipFamily vpplink.IPFamily) {
	if ipFamily.IsIP6 {
		podSpecStatus.V6RPFVrfID = id
	} else {
		podSpecStatus.V4RPFVrfID = id
	}
}
