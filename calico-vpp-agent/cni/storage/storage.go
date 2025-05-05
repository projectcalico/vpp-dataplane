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
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	CniServerStateFileVersion = 9  // Used to ensure compatibility wen we reload data
	MaxApiTagLen              = 63 /* No more than 64 characters in API tags */
	VrfTagHashLen             = 8  /* how many hash charatecters (b64) of the name in tag prefix (useful when trucated) */
)

func isMemif(ifName string) bool {
	return strings.HasPrefix(ifName, "memif")
}

type VppInterfaceType uint8

const (
	VppIfTypeUnknown VppInterfaceType = iota
	VppIfTypeTunTap
	VppIfTypeMemif
	VppIfTypeVCL
)

func (ift VppInterfaceType) String() string {
	switch ift {
	case VppIfTypeUnknown:
		return "Unknown"
	case VppIfTypeTunTap:
		return "TunTap"
	case VppIfTypeMemif:
		return "Memif"
	case VppIfTypeVCL:
		return "VCL"
	default:
		return "Unknown"
	}
}

func getHostEndpointProto(proto string) types.IPProto {
	switch proto {
	case "udp":
		return types.UDP
	case "sctp":
		return types.SCTP
	case "tcp":
		return types.TCP
	default:
		return types.TCP
	}
}

func LocalPodSpecKey(netnsName, interfaceName string) string {
	return fmt.Sprintf("netns:%s,if:%s", netnsName, interfaceName)
}

func (self *LocalPodSpec) Key() string {
	return LocalPodSpecKey(self.NetnsName, self.InterfaceName)
}

func (self *LocalPodSpec) String() string {
	lst := self.ContainerIps
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return fmt.Sprintf("%s [%s]", self.Key(), strings.Join(strLst, ", "))
}

func (self *LocalPodSpec) GetParamsForIfType(ifType VppInterfaceType) (swIfIndex uint32, isL3 bool) {
	switch ifType {
	case VppIfTypeTunTap:
		return self.Status.TunTapSwIfIndex, *self.IfSpec.IsL3
	case VppIfTypeMemif:
		if !*config.GetCalicoVppFeatureGates().MemifEnabled {
			return types.InvalidID, true
		}
		return self.Status.MemifSwIfIndex, *self.PBLMemifSpec.IsL3
	default:
		return types.InvalidID, true
	}
}

func (self *LocalPodSpec) GetBuffersNeeded() uint64 {
	var buffersNeededForThisPod uint64
	buffersNeededForThisPod += self.IfSpec.GetBuffersNeeded()
	if self.NetworkName == "" && self.EnableMemif {
		buffersNeededForThisPod += self.PBLMemifSpec.GetBuffersNeeded()
	}
	return buffersNeededForThisPod
}

// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalIfPortConfigs struct {
	Start uint16
	End   uint16
	Proto types.IPProto
}

func (pc *LocalIfPortConfigs) String() string {
	return fmt.Sprintf("%s %d-%d", pc.Proto.String(), pc.Start, pc.End)
}

// XXX: Increment CniServerStateFileVersion when changing this struct
type HostPortBinding struct {
	HostPort      uint16
	HostIP        net.IP
	ContainerPort uint16
	EntryID       uint32
	Protocol      types.IPProto
}

// LocalPodSpecStatus contains VPP internal ids, mutable fields in AddVppInterface
// We persist them on the disk to avoid rescanning when the agent is restarting.
//
// We should be careful during state-reconciliation as they might not be
// valid anymore. VRF tags should provide this guarantee
//
//
// These fields are only a runtime cache, but we also store them
// on the disk for debugging & gracefull restart.
type LocalPodSpecStatus struct {
	MemifSocketId     uint32   `json:"memifSocketId"`
	MemifSwIfIndex    uint32   `json:"memifSwIfIndex"`
	TunTapSwIfIndex   uint32   `json:"tunTapSwIfIndex"`
	LoopbackSwIfIndex uint32   `json:"loopbackSwIfIndex"`
	// PblIndexes is a map from containerIP to PBL index in VPP
	PblIndexes        map[string]uint32 `json:"pblIndexes"`
	V4VrfId   uint32 `json:"v4VrfId"`
	V4RPFVrfId uint32 `json:"v4RPFVrfId"`
	V6VrfId   uint32 `json:"v6VrfId"`
	V6RPFVrfId uint32 `json:"v6RPFVrfId"`
	NeedsSnat bool   `json:"needsSnat"`
}

func NewLocalPodSpecStatus() LocalPodSpecStatus {
	return LocalPodSpecStatus{
		MemifSocketId: vpplink.InvalidID,
		MemifSwIfIndex:  vpplink.InvalidID,
		TunTapSwIfIndex: vpplink.InvalidID,
		LoopbackSwIfIndex: vpplink.InvalidID,
		PblIndexes: make(map[string]uint32),
 		V4VrfId: vpplink.InvalidID,
 		V4RPFVrfId: vpplink.InvalidID,
		V6VrfId: vpplink.InvalidID,
		V6RPFVrfId: vpplink.InvalidID,
	}
}


// LocalPodSpec represents the configuration and runtime status of
// a given pod & interface couple. It is persisted on disk to allow
// seemless restarts
//
// XXX: Increment CniServerStateFileVersion when changing this struct
type LocalPodSpec struct {
	// Status is the runtime Status for this pod & interface couple
	Status LocalPodSpecStatus

	// InterfaceName is the name of the interface this podSpec represents
	InterfaceName     string      `json:"interfaceName"`
	// NetnsName is the name of the netns mounted on the host
	NetnsName         string      `json:"netnsName"`
	// AllowIpForwarding controls whether we allow IP forwarding in the pod
	AllowIpForwarding bool        `json:"allowIpForwarding"`
	// Routes are routes to be configured in the pod
	Routes            []net.IPNet `json:"routes"`
	// ContainerIps are the IPs of the container (typically v4 and v6)
	ContainerIps      []net.IP    `json:"containerIps"`
	// Mtu is the MTU to configure in the pod on its interface
	Mtu               int         `json:"mtu"`
	// OrchestratorID is a calico/k8s identifier for this pod
	OrchestratorID string `json:"orchestratorID"`
	// WorkloadID is a calico/k8s identifier for this pod
	WorkloadID     string `json:"workloadID"`
	// EndpointID is a calico/k8s identifier for this pod
	EndpointID     string `json:"endpointID"`
	// HostPorts are the HostPorts configured for this Pod
	HostPorts []HostPortBinding `json:"hostPorts"`
	// IfPortConfigs specifies a 2-tuple based (port and protocol) set
	// of rules allowing to split traffic between two interfaces,
	// typically a memif and a tuntap
	IfPortConfigs []LocalIfPortConfigs `json:"ifPortConfigs"`
	// PortFilteredIfType is the interface type to which we will forward
	// traffic MATCHING the portConfigs
	PortFilteredIfType VppInterfaceType `json:"portFilteredIfType"`
	// DefaultIfType is the interface type to which we will traffic
	// not matching portConfigs
	DefaultIfType VppInterfaceType `json:"defaultIfType"`
	// EnableVCL tells whether the pod asked for VCL
	EnableVCL bool `json:"enableVCL"`
	// EnableMemif tells whether the pod asked for memif
	EnableMemif bool `json:"enableMemif"`

	// IfSpec is the interface specification (rx queues, queue sizes,...)
	IfSpec config.InterfaceSpec `json:"ifSpec"`
	// PBLMemifSpec is the additional interface specification
	// (rx queues, queue sizes,...)
	PBLMemifSpec config.InterfaceSpec `json:"pblMemifSpec"`

	// AllowedSpoofingSources is the list of prefixes from which the pod is allowed
	// to send traffic
	AllowedSpoofingSources []net.IPNet `json:"allowedSpoofingPrefixes"`

	// NetworkName contains the name of the network this podSpec belongs
	// to. Keeping in mind that for multi net, PodSpec are duplicated for
	// every interface the pod has.
	// It is set to the empty string for multinet disabled and to represent
	// the default network.
	NetworkName string `json:"networkName"`
}

func (self *LocalPodSpec) Copy() LocalPodSpec {
	newPs := *self
	newPs.Routes = append(make([]net.IPNet, 0), self.Routes...)
	newPs.ContainerIps = append(make([]net.IP, 0), self.ContainerIps...)
	newPs.HostPorts = append(make([]HostPortBinding, 0), self.HostPorts...)
	newPs.IfPortConfigs = append(make([]LocalIfPortConfigs, 0), self.IfPortConfigs...)
	newPs.AllowedSpoofingSources = append(make([]net.IPNet, 0), self.AllowedSpoofingSources...)
	newPs.Status.PblIndexes = make(map[string]uint32)
	for k, v := range self.Status.PblIndexes {
		newPs.Status.PblIndexes[k] = v
	}
	return newPs

}

func getDefaultIfSpec(isL3 bool) config.InterfaceSpec {
	return config.InterfaceSpec{
		NumRxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumRxQueues,
		NumTxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumTxQueues,
		RxQueueSize: vpplink.DefaultIntTo(
			config.GetCalicoVppInterfaces().DefaultPodIfSpec.RxQueueSize,
			vpplink.DEFAULT_QUEUE_SIZE,
		),
		TxQueueSize: vpplink.DefaultIntTo(
			config.GetCalicoVppInterfaces().DefaultPodIfSpec.TxQueueSize,
			vpplink.DEFAULT_QUEUE_SIZE,
		),
		IsL3: &isL3,
	}
}

func NewLocalPodSpecFromAdd(request *cniproto.AddRequest, nodeBGPSpec *common.LocalNodeSpec) (*LocalPodSpec, error) {
	podSpec := LocalPodSpec{
		InterfaceName:     request.GetInterfaceName(),
		NetnsName:         request.GetNetns(),
		AllowIpForwarding: request.GetSettings().GetAllowIpForwarding(),
		Routes:            make([]net.IPNet, 0),
		ContainerIps:      make([]net.IP, 0),
		Mtu:               int(request.GetSettings().GetMtu()),

		IfPortConfigs: make([]LocalIfPortConfigs, 0),

		OrchestratorID: request.Workload.Orchestrator,
		WorkloadID:     request.Workload.Namespace + "/" + request.Workload.Pod,
		EndpointID:     request.Workload.Endpoint,
		HostPorts:      make([]HostPortBinding, 0),

		/* defaults */
		IfSpec:       getDefaultIfSpec(true /* isL3 */),
		PBLMemifSpec: getDefaultIfSpec(false /* isL3 */),

		NetworkName: request.DataplaneOptions["network_name"],
		Status: NewLocalPodSpecStatus(),
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

	for _, port := range request.Workload.Ports {
		if port.HostPort != 0 {
			hostPortBinding := HostPortBinding{
				HostPort:      uint16(port.HostPort),
				HostIP:        net.ParseIP(port.HostIp),
				ContainerPort: uint16(port.Port),
			}
			_ = hostPortBinding.Protocol.UnmarshalText([]byte(port.Protocol))
			if hostPortBinding.HostIP == nil || hostPortBinding.HostIP.IsUnspecified() {
				if nodeBGPSpec != nil && nodeBGPSpec.IPv4Address != nil {
					// default to node IP
					hostPortBinding.HostIP = net.ParseIP(
						nodeBGPSpec.IPv4Address.IP.String(),
					)
				}
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
		containerIp, _, err := net.ParseCIDR(requestContainerIP.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("Cannot parse address: %s", requestContainerIP.GetAddress())
		}
		// We ignore the prefix len set on the address,
		// for a tun it doesn't make sense
		podSpec.ContainerIps = append(podSpec.ContainerIps, containerIp)
	}
	workload := request.GetWorkload()
	if workload != nil {
		err := parsePodAnnotations(&podSpec, workload.Annotations)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse pod Annotations")
		}
	}

	if podSpec.DefaultIfType == VppIfTypeUnknown {
		podSpec.DefaultIfType = VppIfTypeTunTap
	}

	return &podSpec, nil
}

func (hp *HostPortBinding) String() string {
	s := fmt.Sprintf("%s %s:%d", hp.Protocol.String(), hp.HostIP, hp.HostPort)
	s += fmt.Sprintf(" cport=%d", hp.ContainerPort)
	s += fmt.Sprintf(" id=%d", hp.EntryID)
	return s
}

/* 8 base64 character hash */
func hash(text string) string {
	h := sha512.Sum512([]byte(text))
	return base64.StdEncoding.EncodeToString(h[:])[:VrfTagHashLen]
}

func TruncateStr(text string, size int) string {
	if len(text) > size {
		return text[:size]
	}
	return text
}

func (self *LocalPodSpec) GetVrfTag(ipFamily vpplink.IpFamily, custom string) string {
	h := hash(fmt.Sprintf("%s%s%s%s", ipFamily.ShortStr, self.NetnsName, self.InterfaceName, custom))
	s := fmt.Sprintf("%s-%s-%s%s-%s", h, ipFamily.ShortStr, self.InterfaceName, custom, filepath.Base(self.NetnsName))
	return TruncateStr(s, MaxApiTagLen)
}

func (self *LocalPodSpec) GetInterfaceTag(prefix string) string {
	h := hash(fmt.Sprintf("%s%s%s", prefix, self.NetnsName, self.InterfaceName))
	s := fmt.Sprintf("%s-%s-%s", h, self.InterfaceName, filepath.Base(self.NetnsName))
	return TruncateStr(s, MaxApiTagLen)
}

func (self *LocalPodSpec) GetContainerIps() (containerIps []*net.IPNet) {
	containerIps = make([]*net.IPNet, 0, len(self.ContainerIps))
	for _, containerIp := range self.ContainerIps {
		containerIps = append(containerIps, &net.IPNet{
			IP:   containerIp,
			Mask: common.GetMaxCIDRMask(containerIp),
		})
	}
	return containerIps
}

func (self *LocalPodSpec) Hasv46() (hasv4 bool, hasv6 bool) {
	hasv4 = false
	hasv6 = false
	for _, containerIP := range self.ContainerIps {
		if containerIP.To4() == nil {
			hasv6 = true
		} else {
			hasv4 = true
		}
	}
	return hasv4, hasv6
}

func (self *LocalPodSpec) GetVrfId(ipFamily vpplink.IpFamily) uint32 {
	if ipFamily.IsIp6 {
		return self.Status.V6VrfId
	} else {
		return self.Status.V4VrfId
	}
}

func (self *LocalPodSpec) GetRPFVrfId(ipFamily vpplink.IpFamily) uint32 {
	if ipFamily.IsIp6 {
		return self.Status.V6RPFVrfId
	} else {
		return self.Status.V4RPFVrfId
	}
}

func (self *LocalPodSpec) SetVrfId(id uint32, ipFamily vpplink.IpFamily) {
	if ipFamily.IsIp6 {
		self.Status.V6VrfId = id
	} else {
		self.Status.V4VrfId = id
	}
}

func (self *LocalPodSpec) SetRPFVrfId(id uint32, ipFamily vpplink.IpFamily) {
	if ipFamily.IsIp6 {
		self.Status.V6RPFVrfId = id
	} else {
		self.Status.V4RPFVrfId = id
	}
}

type SavedState struct {
	Version    int            `json:"version"`
	SpecsCount int            `json:"specsCount"`
	Specs      []LocalPodSpec `json:"specs"`
}

func PersistCniServerState(podInterfaceMap map[string]LocalPodSpec, fname string) (err error) {
	tmpFile := fmt.Sprintf("%s~", fname)
	state := &SavedState{
		Version:    CniServerStateFileVersion,
		SpecsCount: len(podInterfaceMap),
		Specs:      make([]LocalPodSpec, 0, len(podInterfaceMap)),
	}
	for _, podSpec := range podInterfaceMap {
		state.Specs = append(state.Specs, podSpec)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.Wrap(err, "Error encoding pod data")
	}

	err = os.WriteFile(tmpFile, data, 0200)
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
	state := &SavedState{}
	data, err := os.ReadFile(fname)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		} else {
			return nil, errors.Wrapf(err, "Error reading file %s", fname)
		}
	}
	err = json.Unmarshal(data, state)
	if err != nil {
		return nil, errors.Wrapf(err, "Error unmarshaling json state")
	}
	if state.Version != CniServerStateFileVersion {
		// When adding new versions, we need to keep loading old versions or some pods
		// will remain disconnected forever after an upgrade
		return nil, fmt.Errorf("Unsupported save file version: %d", state.Version)
	}
	return state.Specs, nil
}
