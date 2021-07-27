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
	CniServerStateFileVersion = 3 // Used to ensure compatibility wen we reload data
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
	VppTun   VppInterfaceType = iota
	VppMemif VppInterfaceType = iota

	VppTunName   = "tun"
	VppMemifName = "memif"
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
	return fmt.Sprintf("%s--%s", ps.NetnsName, ps.InterfaceName)
}

func (ps *LocalPodSpec) String() string {
	lst := ps.ContainerIps
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return fmt.Sprintf("%s: %s", ps.Key(), strings.Join(strLst, ", "))
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

type LocalIfPortConfigs struct {
	Port   uint16
	Proto  types.IPProto
	IfType VppInterfaceType
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

	IfPortConfigsLen int `struc:"int16,sizeof=IfPortConfigs"`
	IfPortConfigs    []LocalIfPortConfigs
	DefaultIfType    VppInterfaceType

	MemifSocketId uint32

	/* Caching */
	NeedsSnat bool
}

func (ps *LocalPodSpec) HasIfType(ifType VppInterfaceType) bool {
	if ifType == ps.DefaultIfType {
		return true
	}
	for _, pc := range ps.IfPortConfigs {
		if ifType == pc.IfType {
			return true
		}
	}
	return false
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
