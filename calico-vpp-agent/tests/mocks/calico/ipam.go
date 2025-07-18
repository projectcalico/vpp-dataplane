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
	"fmt"
	"net"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// IpamInterfaceStub is stub implementation of ipam.Interface. It is used for IP address management.
type IpamInterfaceStub struct {
	// AssignedIPCounter holds the count of all assigned IP addresses. It is used in simplified assigning
	// of new IP addresses.
	AssignedIPCounter int
}

// NewIpamInterfaceStub creates new IpamInterfaceStub instance
func NewIpamInterfaceStub() *IpamInterfaceStub {
	return &IpamInterfaceStub{}
}

// AutoAssign automatically assigns one or more IP addresses as specified by the
// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
// and the list of the assigned IPv6 addresses in IPNet format.
// The returned IPNet represents the allocation block from which the IP was allocated,
// which is useful for dataplanes that need to know the subnet (such as Windows).
//
// In case of error, returns the IPs allocated so far along with the error.
func (iis *IpamInterfaceStub) AutoAssign(ctx context.Context, args ipam.AutoAssignArgs) (*ipam.IPAMAssignments,
	*ipam.IPAMAssignments, error) {
	if args.Num4 > 0 {
		return nil, nil, fmt.Errorf("ipv4 not supported")
	}
	if args.Num6 > 1 {
		return nil, nil, fmt.Errorf("multiple IPv6 address assigment is not supported")
	}
	if len(args.IPv6Pools) == 0 {
		return nil, nil, fmt.Errorf("supporting IPv6 address assigment only from IPv6Pools specified " +
			"in args parameter")
	}

	// getting new assigned IP addresses by simple integer(=IP Address) increasing
	// (ignoring that counter should be for each ip pool and using just one global counter -> could have ip address
	// holes, but that should be ok for testing )
	iis.AssignedIPCounter++
	newIP := args.IPv6Pools[0].NthIP(iis.AssignedIPCounter).IP

	// packing new assigned IP address into needed structures
	newIPNet := cnet.IPNet{
		IPNet: net.IPNet{
			IP:   newIP,
			Mask: args.IPv6Pools[0].Mask,
		},
	}
	ipv6Assignments := &ipam.IPAMAssignments{
		IPs:          []cnet.IPNet{newIPNet},
		IPVersion:    6,
		NumRequested: args.Num6,
	}

	// ignoring IPv4 assignments, they are unsupported
	return nil, ipv6Assignments, nil
}

// AssignIP assigns the provided IP address to the provided host.  The IP address
// must fall within a configured pool.  AssignIP will claim block affinity as needed
// in order to satisfy the assignment.  An error will be returned if the IP address
// is already assigned, or if StrictAffinity is enabled and the address is within
// a block that does not have affinity for the given host.
func (iis *IpamInterfaceStub) AssignIP(ctx context.Context, args ipam.AssignIPArgs) error {
	panic("not implemented")
}

// ReleaseIPs releases any of the given IP addresses that are currently assigned,
// so that they are available to be used in another assignment.
func (iis *IpamInterfaceStub) ReleaseIPs(ctx context.Context, ips ...ipam.ReleaseOptions) ([]cnet.IP, error) {
	panic("not implemented")
}

// GetAssignmentAttributes returns the attributes stored with the given IP address
// upon assignment, as well as the handle used for assignment (if any).
func (iis *IpamInterfaceStub) GetAssignmentAttributes(ctx context.Context, addr cnet.IP) (map[string]string,
	*string, error) {
	panic("not implemented")
}

// IPsByHandle returns a list of all IP addresses that have been
// assigned using the provided handle.
func (iis *IpamInterfaceStub) IPsByHandle(ctx context.Context, handleID string) ([]cnet.IP, error) {
	panic("not implemented")
}

// ReleaseByHandle releases all IP addresses that have been assigned
// using the provided handle.  Returns an error if no addresses
// are assigned with the given handle.
func (iis *IpamInterfaceStub) ReleaseByHandle(ctx context.Context, handleID string) error {
	panic("not implemented")
}

// ClaimAffinity claims affinity to the given host for all blocks
// within the given CIDR.  The given CIDR must fall within a configured
// pool. If an empty string is passed as the host, then the value returned by os.Hostname is used.
func (iis *IpamInterfaceStub) ClaimAffinity(ctx context.Context, cidr cnet.IPNet, affinityConfig ipam.AffinityConfig) ([]cnet.IPNet,
	[]cnet.IPNet, error) {
	panic("not implemented")
}

// ReleaseAffinity releases affinity for all blocks within the given CIDR
// on the given host.  If an empty string is passed as the host, then the
// value returned by os.Hostname will be used. If mustBeEmpty is true, then an error
// will be returned if any blocks within the CIDR are not empty - in this case, this
// function may release some but not all blocks within the given CIDR.
func (iis *IpamInterfaceStub) ReleaseAffinity(ctx context.Context, cidr cnet.IPNet, host string,
	mustBeEmpty bool) error {
	panic("not implemented")
}

// ReleaseHostAffinities releases affinity for all blocks that are affine
// to the given host.  If an empty string is passed as the host, the value returned by
// os.Hostname will be used. If mustBeEmpty is true, then an error
// will be returned if any blocks within the CIDR are not empty - in this case, this
// function may release some but not all blocks attached to this host.
func (iis *IpamInterfaceStub) ReleaseHostAffinities(ctx context.Context, affinityConfig ipam.AffinityConfig, mustBeEmpty bool) error {
	panic("not implemented")
}

// ReleasePoolAffinities releases affinity for all blocks within
// the specified pool across all hosts.
func (iis *IpamInterfaceStub) ReleasePoolAffinities(ctx context.Context, pool cnet.IPNet) error {
	panic("not implemented")
}

// ReleaseBlockAffinity releases the affinity of the exact block provided.
func (iis *IpamInterfaceStub) ReleaseBlockAffinity(ctx context.Context, block *model.AllocationBlock,
	mustBeEmpty bool) error {
	panic("not implemented")
}

// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
// has been set, returns a default configuration with StrictAffinity disabled
// and AutoAllocateBlocks enabled.
func (iis *IpamInterfaceStub) GetIPAMConfig(ctx context.Context) (*ipam.IPAMConfig, error) {
	panic("not implemented")
}

// SetIPAMConfig sets global IPAM configuration.  This can only
// be done when there are no allocated blocks and IP addresses.
func (iis *IpamInterfaceStub) SetIPAMConfig(ctx context.Context, cfg ipam.IPAMConfig) error {
	panic("not implemented")
}

// RemoveIPAMHost releases affinity for all blocks on the given host,
// and removes all host-specific IPAM data from the datastore.
// RemoveIPAMHost does not release any IP addresses claimed on the given host.
// If an empty string is passed as the host then the value returned by os.Hostname is used.
func (iis *IpamInterfaceStub) RemoveIPAMHost(ctx context.Context, affinityConfig ipam.AffinityConfig) error {
	panic("not implemented")
}

// GetUtilization returns IP utilization info for the specified pools, or for all pools.
func (iis *IpamInterfaceStub) GetUtilization(ctx context.Context, args ipam.GetUtilizationArgs) (
	[]*ipam.PoolUtilization, error) {
	panic("not implemented")
}

// EnsureBlock returns single IPv4/IPv6 IPAM block for a host as specified by the provided BlockArgs.
// If there is no block allocated already for this host, allocate one and return its' CIDR.
// Otherwise, return the CIDR of the IPAM block allocated for this host.
// It returns IPv4, IPv6 block CIDR and any error encountered.
func (iis *IpamInterfaceStub) EnsureBlock(ctx context.Context, args ipam.BlockArgs) (*cnet.IPNet, *cnet.IPNet, error) {
	panic("not implemented")
}
