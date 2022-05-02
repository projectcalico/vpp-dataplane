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

package common

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	bgpapi "github.com/osrg/gobgp/api"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

var (
	ContainerSideMacAddress, _ = net.ParseMAC("02:00:00:00:00:01")
)

const (
	DefaultVRFIndex = uint32(0)
	PuntTableId     = uint32(1)
	PodVRFIndex     = uint32(2)
)

func CreateVppLink(socket string, log *logrus.Entry) (vpp *vpplink.VppLink, err error) {
	// Get an API connection, with a few retries to accomodate VPP startup time
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(socket, log)
		if err != nil {
			if i < 5 {
				/* do not warn, it is probably fine */
				log.Infof("Waiting for VPP... [%d/10]", i)
			} else {
				log.Warnf("Waiting for VPP... [%d/10] %v", i, err)
			}
			err = nil
			time.Sleep(2 * time.Second)
		} else {
			// Try a simple API message to verify everything is up and running
			version, err := vpp.GetVPPVersion()
			if err != nil {
				log.Warnf("Try [%d/10] broken vpplink: %v", i, err)
				err = nil
				time.Sleep(2 * time.Second)
			} else {
				log.Infof("Connected to VPP version %s", version)
				return vpp, nil
			}
		}
	}
	return nil, errors.Errorf("Cannot connect to VPP after 10 tries")
}

func WaitForVppManager() error {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerStatusFile)
		if err == nil && strings.TrimSpace(string(dat[:])) == "1" {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return errors.Errorf("Vpp manager not ready after 20 tries")
}

func WritePidToFile() error {
	pid := strconv.FormatInt(int64(os.Getpid()), 10)
	return ioutil.WriteFile(config.CalicoVppPidFile, []byte(pid+"\n"), 0400)
}

func SafeFormat(e interface{ String() string }) string {
	if e == nil {
		return ""
	} else {
		return e.String()
	}
}

func FormatSlice(lst []interface{ String() string }) string {
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return strings.Join(strLst, ", ")
}

func getMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func GetMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func ToMaxLenCIDR(addr net.IP) *net.IPNet {
	return &net.IPNet{
		IP:   addr,
		Mask: GetMaxCIDRMask(addr),
	}
}

func FullyQualified(addr net.IP) *net.IPNet {
	return &net.IPNet{
		IP:   addr,
		Mask: GetMaxCIDRMask(addr),
	}
}

// This function and the related mechanism in vpmanager are curently kept around
// in case they're useful for the Host Endpoint policies implementation
func GetVppTapSwifIndex() (swIfIndex uint32, err error) {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerTapIdxFile)
		if err == nil {
			idx, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 32)
			if err == nil && idx != -1 {
				return uint32(idx), nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return 0, errors.Errorf("Vpp-host tap not ready after 20 tries")
}

const (
	aggregatedPrefixSetBaseName = "aggregated"
	hostPrefixSetBaseName       = "host"
	policyBaseName              = "calico_aggr"
)

var (
	BgpFamilyUnicastIPv4VPN = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_MPLS_VPN}
	BgpFamilyUnicastIPv6VPN = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_MPLS_VPN}
	BgpFamilyUnicastIPv4    = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_UNICAST}
	BgpFamilySRv6IPv4       = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_SR_POLICY}
	BgpFamilyUnicastIPv6    = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_UNICAST}
	BgpFamilySRv6IPv6       = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_SR_POLICY}
)

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

func MakePath(prefix string, isWithdrawal bool, nodeIpv4 *net.IP, nodeIpv6 *net.IP, vni uint32, asNumber uint32) (*bgpapi.Path, error) {
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
	var nlri *anypb.Any
	if vni != 0 {
		rdAttr, err := ptypes.MarshalAny(&bgpapi.RouteDistinguisherTwoOctetAS{
			Admin:    64512,
			Assigned: vni,
		})
		if err != nil {
			return nil, err
		}
		nlri, err = ptypes.MarshalAny(&bgpapi.LabeledVPNIPAddressPrefix{
			Prefix:    p.String(),
			PrefixLen: uint32(masklen),
			Rd:        rdAttr,
		})
		if err != nil {
			return nil, err
		}
	} else {
		nlri, err = ptypes.MarshalAny(&bgpapi.IPAddressPrefix{
			Prefix:    p.String(),
			PrefixLen: uint32(masklen),
		})
		if err != nil {
			return nil, err
		}
	}
	var family *bgpapi.Family
	originAttr, err := ptypes.MarshalAny(&bgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	attrs := []*any.Any{originAttr}

	if v4 {
		if nodeIpv4 == nil {
			return nil, fmt.Errorf("No ip4 address for node")
		}
		family = &BgpFamilyUnicastIPv4
		if vni != 0 {
			family = &BgpFamilyUnicastIPv4VPN
		}
		var nhAttr *any.Any

		if config.EnableSRv6 {
			nhAttr, err = ptypes.MarshalAny(&bgpapi.NextHopAttribute{
				NextHop: nodeIpv6.String(),
			})
		} else {
			nhAttr, err = ptypes.MarshalAny(&bgpapi.NextHopAttribute{
				NextHop: nodeIpv4.String(),
			})
		}
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nhAttr)
	} else {
		if nodeIpv6 == nil {
			return nil, fmt.Errorf("No ip6 address for node")
		}
		family = &BgpFamilyUnicastIPv6
		if vni != 0 {
			family = &BgpFamilyUnicastIPv6VPN
		}
		var nlriAttr *anypb.Any
		var familySafi bgpapi.Family_Safi
		if vni != 0 {
			familySafi = bgpapi.Family_SAFI_MPLS_VPN
		} else {
			familySafi = bgpapi.Family_SAFI_UNICAST
		}
		nlriAttr, err = ptypes.MarshalAny(&bgpapi.MpReachNLRIAttribute{
			NextHops: []string{nodeIpv6.String()},
			Nlris:    []*any.Any{nlri},
			Family: &bgpapi.Family{
				Afi:  bgpapi.Family_AFI_IP6,
				Safi: familySafi,
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

func MakePathSRv6Tunnel(localSid net.IP, bSid net.IP, nodeIpv6 net.IP, trafficType int, isWithdrawal bool) (*bgpapi.Path, error) {
	originAttr, err := ptypes.MarshalAny(&bgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	attrs := []*any.Any{originAttr}

	var family *bgpapi.Family
	var nodeIP = nodeIpv6
	var epbs = &bgpapi.SRv6EndPointBehavior{}
	family = &BgpFamilySRv6IPv6
	if trafficType == 4 {
		epbs.Behavior = bgpapi.SRv6Behavior_END_DT4
	} else {
		epbs.Behavior = bgpapi.SRv6Behavior_END_DT6
	}

	nlrisr, err := ptypes.MarshalAny(&bgpapi.SRPolicyNLRI{
		Length:   192,
		Endpoint: nodeIP,
	})

	if err != nil {
		return nil, err
	}
	nhAttr, err := ptypes.MarshalAny(&bgpapi.NextHopAttribute{
		NextHop: nodeIP.String(),
	})
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, nhAttr)

	sid, err := ptypes.MarshalAny(&bgpapi.SRBindingSID{
		SFlag: true,
		IFlag: false,
		Sid:   bSid,
	})

	if err != nil {
		return nil, err
	}
	bsid, err := ptypes.MarshalAny(&bgpapi.TunnelEncapSubTLVSRBindingSID{
		Bsid: sid,
	})
	if err != nil {
		return nil, err
	}

	segment, err := ptypes.MarshalAny(&bgpapi.SegmentTypeB{
		Flags:                     &bgpapi.SegmentFlags{SFlag: true},
		Sid:                       localSid,
		EndpointBehaviorStructure: epbs,
	})
	if err != nil {
		return nil, err
	}
	seglist, err := ptypes.MarshalAny(&bgpapi.TunnelEncapSubTLVSRSegmentList{
		Weight: &bgpapi.SRWeight{
			Flags:  0,
			Weight: 12,
		},
		Segments: []*any.Any{segment},
	})
	if err != nil {
		return nil, err
	}
	pref, err := ptypes.MarshalAny(&bgpapi.TunnelEncapSubTLVSRPreference{
		Flags:      0,
		Preference: 11,
	})
	if err != nil {
		return nil, err
	}

	pri, err := ptypes.MarshalAny(&bgpapi.TunnelEncapSubTLVSRPriority{
		Priority: 10,
	})
	if err != nil {
		return nil, err
	}
	// Tunnel Encapsulation attribute for SR Policy
	tun, err := ptypes.MarshalAny(&bgpapi.TunnelEncapAttribute{
		Tlvs: []*bgpapi.TunnelEncapTLV{
			{
				Type: 15,
				Tlvs: []*any.Any{bsid, seglist, pref, pri},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, tun)

	return &bgpapi.Path{
		Nlri:       nlrisr,
		IsWithdraw: isWithdrawal,
		Pattrs:     attrs,
		Age:        ptypes.TimestampNow(),
		Family:     family,
	}, nil

}

type ChangeType int

/**
 * Change types are flags so that you can check for multiple
 * fields changing with an OR
 */
const (
	ChangeSame    ChangeType = 0
	ChangeAdded   ChangeType = 1
	ChangeDeleted ChangeType = 2
	ChangeUpdated ChangeType = 4
)

func GetStringChangeType(old, new string) ChangeType {
	if old == new && new == "" {
		return ChangeSame
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

type NodeConnectivity struct {
	Dst              net.IPNet
	NextHop          net.IP
	ResolvedProvider string
	Custom           interface{}
	Vni              uint32
}

func (cn *NodeConnectivity) String() string {
	return fmt.Sprintf("%s-%s-%s", cn.Dst.String(), cn.NextHop.String(), fmt.Sprint(cn.Vni))
}

type SRv6Tunnel struct {
	Dst      net.IP
	Bsid     net.IP
	Policy   *types.SrPolicy
	Sid      net.IP
	Behavior uint8
	Priority uint32
}

func GetBGPSpecAddresses(nodeBGPSpec *oldv3.NodeBGPSpec) (*net.IP, *net.IP) {
	var ip4 *net.IP
	var ip6 *net.IP
	if nodeBGPSpec.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(nodeBGPSpec.IPv4Address)
		if err == nil {
			ip4 = &addr
		}
	}
	if nodeBGPSpec.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(nodeBGPSpec.IPv6Address)
		if err == nil {
			ip6 = &addr
		}
	}
	return ip4, ip6
}

func GetBGPSpecIPNet(nodeBGPSpec *oldv3.NodeBGPSpec) (ip4 *net.IPNet, ip6 *net.IPNet) {
	if nodeBGPSpec.IPv4Address != "" {
		_, ipNet, err := net.ParseCIDR(nodeBGPSpec.IPv4Address)
		if err == nil {
			ip4 = ipNet
		}
	}
	if nodeBGPSpec.IPv6Address != "" {
		_, ipNet, err := net.ParseCIDR(nodeBGPSpec.IPv6Address)
		if err == nil {
			ip6 = ipNet
		}
	}
	return ip4, ip6
}

func GetNodeSpecAddresses(node *oldv3.Node) (string, string) {
	nodeIP4 := ""
	nodeIP6 := ""
	if node.Spec.BGP.IPv4Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err == nil {
			nodeIP4 = addr.String()
		}
	}
	if node.Spec.BGP.IPv6Address != "" {
		addr, _, err := net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err == nil {
			nodeIP6 = addr.String()
		}
	}
	return nodeIP4, nodeIP6
}

func formatBGPConfiguration(conf *calicov3.BGPConfigurationSpec) string {
	if conf == nil {
		return "<nil>"
	}
	meshConfig := "<nil>"
	if conf.NodeToNodeMeshEnabled != nil {
		meshConfig = fmt.Sprintf("%v", *conf.NodeToNodeMeshEnabled)
	}
	asn := "<nil>"
	if conf.ASNumber != nil {
		asn = conf.ASNumber.String()
	}
	return fmt.Sprintf(
		"LogSeverityScreen: %s, NodeToNodeMeshEnabled: %s, ASNumber: %s, ListenPort: %d",
		conf.LogSeverityScreen, meshConfig, asn, conf.ListenPort,
	)
}

func FetchNDataThreads(vpp *vpplink.VppLink, log *logrus.Entry) int {
	nVppWorkers, err := vpp.GetNumVPPWorkers()
	if err != nil {
		log.Panicf("Error getting number of VPP workers: %v", err)
	}
	nDataThreads := nVppWorkers
	if config.IpsecNbAsyncCryptoThread > 0 {
		nDataThreads = nVppWorkers - config.IpsecNbAsyncCryptoThread
		if nDataThreads <= 0 {
			log.Error("Couldn't fullfill request [crypto=%d total=%d]", config.IpsecNbAsyncCryptoThread, nVppWorkers)
			nDataThreads = nVppWorkers
		}
		log.Info("Using ipsec workers [data=%d crypto=%d]", nDataThreads, nVppWorkers-nDataThreads)

	}
	return nDataThreads
}

func CompareIPList(newIPList, oldIPList []net.IP) (added []net.IP, deleted []net.IP, changed bool) {
	oldIPListMap := make(map[string]bool)
	newIPListMap := make(map[string]bool)
	for _, elem := range oldIPList {
		oldIPListMap[elem.String()] = true
	}
	for _, elem := range newIPList {
		newIPListMap[elem.String()] = true
	}
	for _, elem := range oldIPList {
		_, found := newIPListMap[elem.String()]
		if !found {
			deleted = append(deleted, elem)
		}
	}
	for _, elem := range newIPList {
		_, found := oldIPListMap[elem.String()]
		if !found {
			added = append(added, elem)
		}
	}
	changed = len(added)+len(deleted) > 0
	return
}
