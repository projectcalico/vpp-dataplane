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

package model

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func isMemif(ifName string) bool {
	return strings.HasPrefix(ifName, "memif")
}

func LocalPodSpecKey(netnsName, interfaceName string) string {
	return fmt.Sprintf("netns:%s,if:%s", netnsName, interfaceName)
}

// LocalPodSpec represents the configuration and runtime status of
// a given pod & interface couple. It is persisted on disk to allow
// seemless restarts
//
// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalPodSpec struct {
	// PodAnnotations are user-defined parsed properties
	// that control how the pod connectivity is set up
	PodAnnotations `json:"podAnnotations"`
	// LocalPodSpecStatus is the runtime Status for this pod & interface couple
	LocalPodSpecStatus

	// InterfaceName is the name of the interface this podSpec represents
	InterfaceName string `json:"interfaceName"`
	// NetnsName is the name of the netns mounted on the host
	NetnsName string `json:"netnsName"`
	// AllowIPForwarding controls whether we allow IP forwarding in the pod
	AllowIPForwarding bool `json:"allowIpForwarding"`
	// Routes are routes to be configured in the pod
	Routes []net.IPNet `json:"routes"`
	// ContainerIPs are the IPs of the container (typically v4 and v6)
	ContainerIPs []net.IP `json:"containerIps"`
	// Mtu is the MTU to configure in the pod on its interface
	Mtu int `json:"mtu"`
	// OrchestratorID is a calico/k8s identifier for this pod
	OrchestratorID string `json:"orchestratorID"`
	// WorkloadID is a calico/k8s identifier for this pod
	WorkloadID string `json:"workloadID"`
	// EndpointID is a calico/k8s identifier for this pod
	EndpointID string `json:"endpointID"`
	// HostPorts are the HostPorts configured for this Pod
	HostPorts []HostPortBinding `json:"hostPorts"`
	// NetworkName contains the name of the network this podSpec belongs
	// to. Keeping in mind that for multi net, PodSpec are duplicated for
	// every interface the pod has.
	// It is set to the empty string for multinet disabled and to represent
	// the default network.
	NetworkName string `json:"networkName"`
}

func NewLocalPodSpecFromAdd(request *cniproto.AddRequest, nodeBGPSpec *common.LocalNodeSpec) (*LocalPodSpec, error) {
	podAnnotations, err := NewPodAnnotations(
		request.GetInterfaceName(),
		request.GetWorkload().GetAnnotations(),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Cannot parse pod Annotations")
	}
	podSpec := &LocalPodSpec{
		InterfaceName:     request.GetInterfaceName(),
		NetnsName:         request.GetNetns(),
		AllowIPForwarding: request.GetSettings().GetAllowIpForwarding(),
		Routes:            make([]net.IPNet, 0),
		ContainerIPs:      make([]net.IP, 0),
		Mtu:               int(request.GetSettings().GetMtu()),

		OrchestratorID: request.GetWorkload().GetOrchestrator(),
		WorkloadID:     request.GetWorkload().GetNamespace() + "/" + request.GetWorkload().GetPod(),
		EndpointID:     request.GetWorkload().GetEndpoint(),
		HostPorts:      make([]HostPortBinding, 0),

		NetworkName:        request.GetDataplaneOptions()["network_name"],
		PodAnnotations:     *podAnnotations,
		LocalPodSpecStatus: *NewLocalPodSpecStatus(),
	}

	if podSpec.NetworkName != "" {
		if !*config.GetCalicoVppFeatureGates().MultinetEnabled {
			return nil, fmt.Errorf("enable multinet in config for multiple networks")
		}
		if isMemif(podSpec.InterfaceName) {
			if !*config.GetCalicoVppFeatureGates().MemifEnabled {
				return nil, fmt.Errorf("enable memif in config for memif interfaces")
			}
			podSpec.EnableMemif = true
			podSpec.DefaultIfType = VppIfTypeMemif
			podSpec.IfSpec = getDefaultIfSpec(false)
		}
	}

	for _, port := range request.GetWorkload().GetPorts() {
		if port.GetHostPort() != 0 {
			hostPortBinding := HostPortBinding{
				HostPort:      uint16(port.GetHostPort()),
				HostIP:        net.ParseIP(port.GetHostIp()),
				ContainerPort: uint16(port.GetPort()),
			}
			err = hostPortBinding.Protocol.UnmarshalText([]byte(port.GetProtocol()))
			if err != nil {
				return nil, errors.Wrapf(err, "Cannot parse hostport protocol %s", port.GetProtocol())
			}
			podSpec.HostPorts = append(podSpec.HostPorts, hostPortBinding)
		}
	}
	for _, routeStr := range request.GetContainerRoutes() {
		_, route, err := net.ParseCIDR(routeStr)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse container route %s", routeStr)
		}
		podSpec.Routes = append(podSpec.Routes, *route)
	}
	for _, requestContainerIP := range request.GetContainerIps() {
		containerIP, _, err := net.ParseCIDR(requestContainerIP.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("cannot parse address: %s", requestContainerIP.GetAddress())
		}
		// We ignore the prefix len set on the address,
		// for a tun it doesn't make sense
		podSpec.ContainerIPs = append(podSpec.ContainerIPs, containerIP)
	}

	return podSpec, nil
}

func (podSpec *LocalPodSpec) Copy() LocalPodSpec {
	newPs := *podSpec
	newPs.Routes = append(make([]net.IPNet, 0), podSpec.Routes...)
	newPs.ContainerIPs = append(make([]net.IP, 0), podSpec.ContainerIPs...)
	newPs.HostPorts = append(make([]HostPortBinding, 0), podSpec.HostPorts...)
	newPs.IfPortConfigs = append(make([]LocalIfPortConfigs, 0), podSpec.IfPortConfigs...)
	newPs.AllowedSpoofingSources = append(make([]net.IPNet, 0), podSpec.AllowedSpoofingSources...)
	newPs.PblIndexes = make(map[string]uint32)
	for k, v := range podSpec.PblIndexes {
		newPs.PblIndexes[k] = v
	}
	return newPs

}

func (podSpec *LocalPodSpec) Key() string {
	return LocalPodSpecKey(podSpec.NetnsName, podSpec.InterfaceName)
}

func (podSpec *LocalPodSpec) String() string {
	lst := podSpec.ContainerIPs
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return fmt.Sprintf("%s [%s]", podSpec.Key(), strings.Join(strLst, ", "))
}

func (podSpec *LocalPodSpec) GetParamsForIfType(ifType VppInterfaceType) (swIfIndex uint32, isL3 bool) {
	switch ifType {
	case VppIfTypeTunTap:
		return podSpec.TunTapSwIfIndex, *podSpec.IfSpec.IsL3
	case VppIfTypeMemif:
		if !*config.GetCalicoVppFeatureGates().MemifEnabled {
			return types.InvalidID, true
		}
		return podSpec.MemifSwIfIndex, *podSpec.PBLMemifSpec.IsL3
	default:
		return types.InvalidID, true
	}
}

func (podSpec *LocalPodSpec) GetBuffersNeeded() uint64 {
	var buffersNeededForThisPod uint64
	buffersNeededForThisPod += podSpec.IfSpec.GetBuffersNeeded()
	if podSpec.NetworkName == "" && podSpec.EnableMemif {
		buffersNeededForThisPod += podSpec.PBLMemifSpec.GetBuffersNeeded()
	}
	return buffersNeededForThisPod
}

func (podSpec *LocalPodSpec) GetPodNamespace() string {
	splittedWorkloadID := strings.SplitN(podSpec.WorkloadID, "/", 2)
	if len(splittedWorkloadID) != 2 {
		return ""
	}
	return splittedWorkloadID[0]
}

func (podSpec *LocalPodSpec) GetPodName() string {
	splittedWorkloadID := strings.SplitN(podSpec.WorkloadID, "/", 2)
	if len(splittedWorkloadID) != 2 {
		return ""
	}
	return splittedWorkloadID[1]
}

func (podSpec *LocalPodSpec) GetVrfTag(ipFamily vpplink.IPFamily, custom string) string {
	h := config.HashText(fmt.Sprintf("%s%s%s%s", ipFamily.ShortStr, podSpec.NetnsName, podSpec.InterfaceName, custom))
	s := fmt.Sprintf("%s-%s-%s%s-%s", h, ipFamily.ShortStr, podSpec.InterfaceName, custom, filepath.Base(podSpec.NetnsName))
	return config.TruncateStr(s, config.MaxAPITagLen)
}

func (podSpec *LocalPodSpec) GetInterfaceTag(prefix string) string {
	h := config.HashText(fmt.Sprintf("%s%s%s", prefix, podSpec.NetnsName, podSpec.InterfaceName))
	s := fmt.Sprintf("%s-%s-%s", h, podSpec.InterfaceName, filepath.Base(podSpec.NetnsName))
	return config.TruncateStr(s, config.MaxAPITagLen)
}

func (podSpec *LocalPodSpec) GetContainerIPs() (containerIPs []*net.IPNet) {
	containerIPs = make([]*net.IPNet, 0, len(podSpec.ContainerIPs))
	for _, containerIP := range podSpec.ContainerIPs {
		containerIPs = append(containerIPs, &net.IPNet{
			IP:   containerIP,
			Mask: common.GetMaxCIDRMask(containerIP),
		})
	}
	return containerIPs
}

func (podSpec *LocalPodSpec) Hasv46() (hasv4 bool, hasv6 bool) {
	hasv4 = false
	hasv6 = false
	for _, containerIP := range podSpec.ContainerIPs {
		if containerIP.To4() == nil {
			hasv6 = true
		} else {
			hasv4 = true
		}
	}
	return hasv4, hasv6
}

func (podSpec *LocalPodSpec) NeedsSnat(felixServerIpam common.FelixServerIpam, isIP6 bool) bool {
	for _, containerIP := range podSpec.GetContainerIPs() {
		if containerIP.IP.To4() == nil != isIP6 {
			continue
		}
		if felixServerIpam.IPNetNeedsSNAT(containerIP) {
			return true
		}
	}
	return false
}

// LocalIfPortConfigs is the local representation of a
// port range policy splitting traffic between a memif and
// a linux netdev
// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalIfPortConfigs struct {
	// Start is the lowest port of the port range, included
	Start uint16
	// End is the highest port of the port range, included
	End uint16
	// Proto is the protocol for which the policy applies
	Proto types.IPProto
}

func (pc *LocalIfPortConfigs) String() string {
	return fmt.Sprintf("%s %d-%d", pc.Proto.String(), pc.Start, pc.End)
}

// HostPortBinding is the local representation of a
// api/core/v1/types.go:ContainerPort object
// XXX: Increment CniServerStateFileVersion when changing this struct
type HostPortBinding struct {
	// HostPort is the port exposed on the host
	HostPort uint16
	// HostIP is the IP to bind the host port to
	HostIP net.IP
	// ContainerPort is the port exposed on the container
	ContainerPort uint16
	// Protocol for the port (UDP, TCP or SCTP)
	Protocol types.IPProto
	// EntryID is the HostPort cnat translation index in VPP
	EntryID uint32
}

func (hp *HostPortBinding) String() string {
	s := fmt.Sprintf("%s %s:%d", hp.Protocol.String(), hp.HostIP, hp.HostPort)
	s += fmt.Sprintf(" container=%d", hp.ContainerPort)
	s += fmt.Sprintf(" id=%d", hp.EntryID)
	return s
}
