// Copyright (C) 2020 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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

package common

import (
	"fmt"
	"net"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	bgpapi "github.com/osrg/gobgp/api"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	calicov3cli "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/vpp-dataplane/vpplink"
)

const (
	aggregatedPrefixSetBaseName = "aggregated"
	hostPrefixSetBaseName       = "host"
	policyBaseName              = "calico_aggr"
)

var (
	BgpFamilyUnicastIPv4 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_UNICAST}
	BgpFamilyUnicastIPv6 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_UNICAST}
)

// Data managed by the routing server and
// shared by the watchers
// This should be immutable for the lifetime
// of the agent
type RoutingData struct {
	Vpp                   *vpplink.VppLink
	BGPServer             *bgpserver.BgpServer
	HasV4                 bool
	HasV6                 bool
	Ipv4                  net.IP
	Ipv6                  net.IP
	Ipv4Net               *net.IPNet
	Ipv6Net               *net.IPNet
	Client                *calicocli.Client
	Clientv3              calicov3cli.Interface
	BGPConf               *calicov3.BGPConfigurationSpec
	ConnectivityEventChan chan ConnectivityEvent
}

type NodeState struct {
	oldv3.Node
	SweepFlag bool
}

func v46ify(s string, isv6 bool) string {
	if isv6 {
		return s + "-v6"
	} else {
		return s + "-v4"
	}
}

func GetPolicyName(isv6 bool) string {
	return v46ify(policyBaseName, isv6)
}

func GetAggPrefixSetName(isv6 bool) string {
	return v46ify(aggregatedPrefixSetBaseName, isv6)
}

func GetHostPrefixSetName(isv6 bool) string {
	return v46ify(hostPrefixSetBaseName, isv6)
}

func MakePath(prefix string, isWithdrawal bool, nodeIpv4 net.IP, nodeIpv6 net.IP) (*bgpapi.Path, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	p := ipNet.IP
	masklen, _ := ipNet.Mask.Size()
	v4 := true
	if p.To4() == nil {
		v4 = false
	}

	nlri, err := ptypes.MarshalAny(&bgpapi.IPAddressPrefix{
		Prefix:    p.String(),
		PrefixLen: uint32(masklen),
	})
	if err != nil {
		return nil, err
	}
	var family *bgpapi.Family
	originAttr, err := ptypes.MarshalAny(&bgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	attrs := []*any.Any{originAttr}

	if v4 {
		family = &BgpFamilyUnicastIPv4
		nhAttr, err := ptypes.MarshalAny(&bgpapi.NextHopAttribute{
			NextHop: nodeIpv4.String(),
		})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nhAttr)
	} else {
		family = &BgpFamilyUnicastIPv6
		nlriAttr, err := ptypes.MarshalAny(&bgpapi.MpReachNLRIAttribute{
			NextHops: []string{nodeIpv6.String()},
			Nlris:    []*any.Any{nlri},
			Family: &bgpapi.Family{
				Afi:  bgpapi.Family_AFI_IP6,
				Safi: bgpapi.Family_SAFI_UNICAST,
			},
		})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nlriAttr)
	}

	return &bgpapi.Path{
		Nlri:       nlri,
		IsWithdraw: isWithdrawal,
		Pattrs:     attrs,
		Age:        ptypes.TimestampNow(),
		Family:     family,
	}, nil
}

type ChangeType int

const (
	ChangeNone    ChangeType = iota
	ChangeSame    ChangeType = iota
	ChangeAdded   ChangeType = iota
	ChangeDeleted ChangeType = iota
	ChangeUpdated ChangeType = iota
)

func GetStringChangeType(old, new string) ChangeType {
	if old == new && new == "" {
		return ChangeNone
	} else if old == new {
		return ChangeSame
	} else if old == "" {
		return ChangeAdded
	} else if new == "" {
		return ChangeDeleted
	} else {
		return ChangeUpdated
	}
}

type ConnectivityEventType string

const (
	NodeStateChanged   ConnectivityEventType = "NodeStateChanged"
	FelixConfChanged   ConnectivityEventType = "FelixConfChanged"
	IpamConfChanged    ConnectivityEventType = "IpamConfChanged"
	VppRestart         ConnectivityEventType = "VppRestart"
	RescanState        ConnectivityEventType = "RescanState"
	ConnectivtyAdded   ConnectivityEventType = "ConnectivtyAdded"
	ConnectivtyDeleted ConnectivityEventType = "ConnectivtyDeleted"
)

type ConnectivityEvent struct {
	Type ConnectivityEventType

	Old interface{}
	New interface{}
}

type NodeConnectivity struct {
	Dst              net.IPNet
	NextHop          net.IP
	ResolvedProvider string
}

func (cn *NodeConnectivity) String() string {
	return fmt.Sprintf("%s-%s", cn.Dst.String(), cn.NextHop.String())
}
