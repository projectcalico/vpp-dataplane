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

package storage

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	CniServerStateFileVersion = 4 // Used to ensure compatibility wen we reload data
)

// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalIPNet struct {
	MaskSize int    `struc:"int8,sizeof=Mask"`
	IP       net.IP `struc:"[16]byte"`
	Mask     net.IPMask
}

// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalIP struct {
	IP net.IP `struc:"[16]byte"`
}

type VppInterfaceType uint8

const (
	VppIfTypeUnknown VppInterfaceType = iota
	VppIfTypeTunTap
	VppIfTypeMemif
	VppIfTypeVCL
)

func (n *LocalIPNet) String() string {
	ipnet := net.IPNet{
		IP:   n.IP,
		Mask: n.Mask,
	}
	return ipnet.String()
}

func (n *LocalIP) String() string {
	return n.IP.String()
}

func (n *LocalIPNet) UpdateSizes() {
	n.MaskSize = len(n.Mask)
}

func (ps *LocalPodSpec) UpdateSizes() {
	ps.RoutesSize = len(ps.Routes)
	ps.ContainerIpsSize = len(ps.ContainerIps)
	ps.InterfaceNameSize = len(ps.InterfaceName)
	ps.NetnsNameSize = len(ps.NetnsName)
	for _, n := range ps.Routes {
		n.UpdateSizes()
	}
}

func (ps *LocalPodSpec) Key() string {
	return fmt.Sprintf("netns:%s,if:%s", ps.NetnsName, ps.InterfaceName)
}

func (ps *LocalPodSpec) String() string {
	lst := ps.ContainerIps
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return fmt.Sprintf("%s [%s]", ps.Key(), strings.Join(strLst, ", "))
}

func (ps *LocalPodSpec) FullString() string {
	containerIps := ps.ContainerIps
	containerIpsLst := make([]string, 0, len(containerIps))
	for _, e := range containerIps {
		containerIpsLst = append(containerIpsLst, e.String())
	}
	routes := ps.Routes
	routesLst := make([]string, 0, len(routes))
	for _, e := range routes {
		routesLst = append(routesLst, e.String())
	}
	return fmt.Sprintf("InterfaceName: %s\nNetnsName: %s\nAllowIpForwarding:%t\nRoutes: %s\nContainerIps: %s\nOrchestratorID: %s\nWorkloadID: %s\nEndpointID: %s",
		ps.InterfaceName, ps.NetnsName, ps.AllowIpForwarding,
		strings.Join(routesLst, ", "),
		strings.Join(containerIpsLst, ", "),
		ps.OrchestratorID,
		ps.WorkloadID,
		ps.EndpointID,
	)
}

func (ps *LocalPodSpec) GetParamsForIfType(ifType VppInterfaceType) (swIfIndex uint32, isL3 bool) {
	switch ifType {
	case VppIfTypeTunTap:
		return ps.TunTapSwIfIndex, ps.TunTapIsL3
	case VppIfTypeMemif:
		if !config.MemifEnabled {
			return types.InvalidID, true
		}
		return ps.MemifSwIfIndex, ps.MemifIsL3
	default:
		return types.InvalidID, true
	}
}

// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalIfPortConfigs struct {
	Start uint16
	End   uint16
	Proto types.IPProto
}

// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalPodSpec struct {
	InterfaceNameSize int `struc:"int16,sizeof=InterfaceName"`
	InterfaceName     string
	NetnsNameSize     int `struc:"int16,sizeof=NetnsName"`
	NetnsName         string
	AllowIpForwarding bool
	RoutesSize        int `struc:"int16,sizeof=Routes"`
	Routes            []LocalIPNet
	ContainerIpsSize  int `struc:"int16,sizeof=ContainerIps"`
	ContainerIps      []LocalIP
	Mtu               int

	// Pod identifiers
	OrchestratorIDSize int `struc:"int16,sizeof=OrchestratorID"`
	OrchestratorID     string
	WorkloadIDSize     int `struc:"int16,sizeof=WorkloadID"`
	WorkloadID         string
	EndpointIDSize     int `struc:"int16,sizeof=EndpointID"`
	EndpointID         string
	// HostPort
	HostPortsSize int `struc:"int16,sizeof=HostPorts"`
	HostPorts     []HostPortBinding

	IfPortConfigsLen int `struc:"int16,sizeof=IfPortConfigs"`
	IfPortConfigs    []LocalIfPortConfigs
	/* This interface type will traffic MATCHING the portConfigs */
	PortFilteredIfType VppInterfaceType
	/* This interface type will traffic not matching portConfigs */
	DefaultIfType VppInterfaceType
	EnableVCL     bool
	EnableMemif   bool
	MemifIsL3     bool
	TunTapIsL3    bool

	/* VPP internals. Persisting on the disk in the case of the
	 * agent restarting. */
	MemifSocketId     uint32
	TunTapSwIfIndex   uint32
	MemifSwIfIndex    uint32
	LoopbackSwIfIndex uint32
	PblIndexesLen     int `struc:"int16,sizeof=PblIndexes"`
	PblIndexes        []uint32

	V4VrfId uint32
	V6VrfId uint32

	/* Caching */
	NeedsSnat bool
}

// XXX: Increment CniServerStateFileVersion when changing this struct
type HostPortBinding struct {
	HostPort      uint32
	HostIP        net.IP `struc:"[16]byte"`
	ContainerPort uint32
	EntryID       uint32
}

func (ps *LocalPodSpec) GetInterfaceTag(prefix string) string {
	return fmt.Sprintf("%s-%s-%s", prefix, ps.NetnsName, ps.InterfaceName)
}

func (ps *LocalPodSpec) GetPodMtu() int {
	// configure MTU from env var if present or calculate it from host mtu
	if ps.Mtu <= 0 {
		return config.PodMtu
	}
	return ps.Mtu
}

func (ps *LocalPodSpec) GetRoutes() (routes []*net.IPNet) {
	routes = make([]*net.IPNet, 0, len(ps.Routes))
	for _, r := range ps.Routes {
		routes = append(routes, &net.IPNet{
			IP:   r.IP,
			Mask: r.Mask,
		})
	}
	return routes
}

func (ps *LocalPodSpec) GetContainerIps() (containerIps []*net.IPNet) {
	containerIps = make([]*net.IPNet, 0, len(ps.ContainerIps))
	for _, containerIp := range ps.ContainerIps {
		containerIps = append(containerIps, &net.IPNet{
			IP:   containerIp.IP,
			Mask: common.GetMaxCIDRMask(containerIp.IP),
		})
	}
	return containerIps
}

func (ps *LocalPodSpec) Hasv46() (hasv4 bool, hasv6 bool) {
	hasv4 = false
	hasv6 = false
	for _, containerIP := range ps.ContainerIps {
		if containerIP.IP.To4() == nil {
			hasv6 = true
		} else {
			hasv4 = true
		}
	}
	return hasv4, hasv6
}

func (ps *LocalPodSpec) GetVrfId(isV6 bool) uint32 {
	if isV6 {
		return ps.V6VrfId
	} else {
		return ps.V4VrfId
	}
}

func (ps *LocalPodSpec) SetVrfId(id uint32, isV6 bool) {
	if isV6 {
		ps.V6VrfId = id
	} else {
		ps.V4VrfId = id
	}
}

type SavedState struct {
	Version    int `struc:"int32"`
	SpecsCount int `struc:"int32,sizeof=Specs"`
	Specs      []LocalPodSpec
}

func PersistCniServerState(podInterfaceMap map[string]LocalPodSpec, fname string) (err error) {
	var buf bytes.Buffer
	tmpFile := fmt.Sprintf("%s~", fname)
	state := &SavedState{
		Version:    CniServerStateFileVersion,
		SpecsCount: len(podInterfaceMap),
		Specs:      make([]LocalPodSpec, 0, len(podInterfaceMap)),
	}
	for _, podSpec := range podInterfaceMap {
		state.Specs = append(state.Specs, podSpec)
	}
	err = struc.Pack(&buf, state)
	if err != nil {
		return errors.Wrap(err, "Error encoding pod data")
	}

	err = ioutil.WriteFile(tmpFile, buf.Bytes(), 0200)
	if err != nil {
		return errors.Wrapf(err, "Error writing file %s", tmpFile)
	}
	err = os.Rename(tmpFile, fname)
	if err != nil {
		return errors.Wrapf(err, "Error moving file %s", tmpFile)
	}
	return nil
}

func LoadCniServerState(fname string) ([]LocalPodSpec, error) {
	var state SavedState
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // No state to load
		} else {
			return nil, errors.Wrapf(err, "Error reading file %s", fname)
		}
	}
	buf := bytes.NewBuffer(data)
	err = struc.Unpack(buf, &state)
	if err != nil {
		return nil, errors.Wrapf(err, "Error unpacking")
	}
	if state.Version != CniServerStateFileVersion {
		// When adding new versions, we need to keep loading old versions or some pods
		// will remain disconnected forever after an upgrade
		return nil, fmt.Errorf("Unsupported save file version: %d", state.Version)
	}
	return state.Specs, nil
}
