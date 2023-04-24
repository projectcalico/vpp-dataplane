// Copyright (c) 2022 Cisco and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calico

import (
	"context"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

// CalicoClientStub is stub implementation of clientv3.Interface. It is used for communication with other Calico parts.
type CalicoClientStub struct {
	IPPoolsStub *IPPoolsStub
	IPAMStub    *IpamInterfaceStub
	NodesMock   *NodesMock
}

// NewCalicoClientStub creates new CalicoClientStub instance
func NewCalicoClientStub() *CalicoClientStub {
	return &CalicoClientStub{
		IPPoolsStub: NewIPPoolsStub(),
		IPAMStub:    NewIpamInterfaceStub(),
		NodesMock:   NewNodesMock(),
	}
}

// IPPools returns an interface for managing IP pool resources.
func (cc *CalicoClientStub) IPPools() clientv3.IPPoolInterface {
	return cc.IPPoolsStub
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (cc *CalicoClientStub) IPAM() ipam.Interface {
	return cc.IPAMStub
}

// Nodes returns an interface for managing node resources.
func (cc *CalicoClientStub) Nodes() clientv3.NodeInterface {
	return cc.NodesMock
}

// GlobalNetworkPolicies returns an interface for managing global network policy resources.
func (cc *CalicoClientStub) GlobalNetworkPolicies() clientv3.GlobalNetworkPolicyInterface {
	panic("not implemented")
}

// NetworkPolicies returns an interface for managing namespaced network policy resources.
func (cc *CalicoClientStub) NetworkPolicies() clientv3.NetworkPolicyInterface {
	panic("not implemented")
}

// IPReservations returns an interface for managing IP reservation resources.
func (cc *CalicoClientStub) IPReservations() clientv3.IPReservationInterface {
	panic("not implemented")
}

// Profiles returns an interface for managing profile resources.
func (cc *CalicoClientStub) Profiles() clientv3.ProfileInterface {
	panic("not implemented")
}

// GlobalNetworkSets returns an interface for managing global network sets resources.
func (cc *CalicoClientStub) GlobalNetworkSets() clientv3.GlobalNetworkSetInterface {
	panic("not implemented")
}

// NetworkSets returns an interface for managing network sets resources.
func (cc *CalicoClientStub) NetworkSets() clientv3.NetworkSetInterface {
	panic("not implemented")
}

// HostEndpoints returns an interface for managing host endpoint resources.
func (cc *CalicoClientStub) HostEndpoints() clientv3.HostEndpointInterface {
	panic("not implemented")
}

// WorkloadEndpoints returns an interface for managing workload endpoint resources.
func (cc *CalicoClientStub) WorkloadEndpoints() clientv3.WorkloadEndpointInterface {
	panic("not implemented")
}

// BGPPeers returns an interface for managing BGP peer resources.
func (cc *CalicoClientStub) BGPPeers() clientv3.BGPPeerInterface {
	panic("not implemented")
}

// BGPConfigurations returns an interface for managing the BGP configuration resources.
func (cc *CalicoClientStub) BGPConfigurations() clientv3.BGPConfigurationInterface {
	panic("not implemented")
}

// FelixConfigurations returns an interface for managing the Felix configuration resources.
func (cc *CalicoClientStub) FelixConfigurations() clientv3.FelixConfigurationInterface {
	panic("not implemented")
}

// ClusterInformation returns an interface for managing the cluster information resource.
func (cc *CalicoClientStub) ClusterInformation() clientv3.ClusterInformationInterface {
	panic("not implemented")
}

// KubeControllersConfiguration returns an interface for managing the
// KubeControllersConfiguration resource.
func (cc *CalicoClientStub) KubeControllersConfiguration() clientv3.KubeControllersConfigurationInterface {
	panic("not implemented")
}

// CalicoNodeStatus returns an interface for managing CalicoNodeStatus resources.
func (cc *CalicoClientStub) CalicoNodeStatus() clientv3.CalicoNodeStatusInterface {
	panic("not implemented")
}

// IPAMConfig returns an interface for managing IPAMConfig resources.
func (cc *CalicoClientStub) IPAMConfig() clientv3.IPAMConfigInterface {
	panic("not implemented")
}

// BlockAffinities returns an interface for viewing IPAM block affinity resources.
func (cc *CalicoClientStub) BlockAffinities() clientv3.BlockAffinityInterface {
	panic("not implemented")
}

func (cc *CalicoClientStub) BGPFilter() clientv3.BGPFilterInterface {
	panic("not implemented")
}

// EnsureInitialized is used to ensure the backend datastore is correctly
// initialized for use by Calico.  This method may be called multiple times, and
// will have no effect if the datastore is already correctly initialized.
// Most Calico deployment scenarios will automatically implicitly invoke this
// method and so a general consumer of this API can assume that the datastore
// is already initialized.
func (cc *CalicoClientStub) EnsureInitialized(ctx context.Context, calicoVersion, clusterType string) error {
	panic("not implemented")
}
