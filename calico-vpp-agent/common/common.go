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
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/config"

	bgpapi "github.com/osrg/gobgp/v3/api"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/projectcalico/calico/felix/proto"
	apb "google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

var (
	ContainerSideMacAddress, _ = net.ParseMAC("02:00:00:00:00:01")
	VppManagerInfo             *config.VppManagerInfo
)

const (
	DefaultVRFIndex = uint32(0)
	PuntTableID     = uint32(1)
	PodVRFIndex     = uint32(2)
)

type FelixServerIpam interface {
	IPNetNeedsSNAT(prefix *net.IPNet) bool
	GetPrefixIPPool(prefix *net.IPNet) *proto.IPAMPool
}

type LocalNodeSpec struct {
	ASNumber    *numorstring.ASNumber
	Labels      map[string]string
	Name        string
	IPv4Address *net.IPNet
	IPv6Address *net.IPNet
}

func NewLocalNodeSpec(msg *proto.HostMetadataV4V6Update) (*LocalNodeSpec, error) {
	localNodeSpec := &LocalNodeSpec{
		Name:   msg.Hostname,
		Labels: msg.Labels,
	}
	if msg.GetIpv4Addr() != "" {
		ip4, ip4net, err := net.ParseCIDR(msg.GetIpv4Addr())
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse Ipv4Addr %s", msg.GetIpv4Addr())
		}
		ip4net.IP = ip4
		localNodeSpec.IPv4Address = ip4net
	}
	if msg.GetIpv6Addr() != "" {
		ip6, ip6net, err := net.ParseCIDR(msg.GetIpv6Addr())
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse Ipv6Addr %s", msg.GetIpv6Addr())
		}
		ip6net.IP = ip6
		localNodeSpec.IPv6Address = ip6net
	}
	if msg.GetAsnumber() != "" {
		asn, err := numorstring.ASNumberFromString(msg.GetAsnumber())
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse Asnumber %s", msg.GetAsnumber())
		}
		localNodeSpec.ASNumber = &asn
	}
	return localNodeSpec, nil
}

type NodeWireguardPublicKey struct {
	Name               string
	WireguardPublicKey string
}

// CreateVppLink creates new link to VPP and waits for VPP to be up and running (by using simple VPP API call)
func CreateVppLink(socket string, log *logrus.Entry) (vpp *vpplink.VppLink, err error) {
	return CreateVppLinkInRetryLoop(socket, log, 20*time.Second, 2*time.Second)
}

// CreateVppLinkInRetryLoop creates new link to VPP and waits for VPP to be up and running (by using simple
// VPP API call). This process is retried in a loop and has a timeout limit.
func CreateVppLinkInRetryLoop(socket string, log *logrus.Entry, timeout time.Duration,
	retry time.Duration) (vpp *vpplink.VppLink, err error) {
	// Get an API connection, with a few retries to accommodate VPP startup time
	maxRetry := int(math.Round(float64(timeout.Nanoseconds() / retry.Nanoseconds())))
	for i := 0; i < maxRetry; i++ {
		vpp, err = vpplink.NewVppLink(socket, log)
		if err != nil {
			if i < (maxRetry / 2) {
				/* do not warn, it is probably fine */
				log.Infof("Waiting for VPP... [%d/%d]", i, maxRetry)
			} else {
				log.Warnf("Waiting for VPP... [%d/%d] %v", i, maxRetry, err)
			}
			time.Sleep(retry)
		} else {
			// Try a simple API message to verify everything is up and running
			version, err := vpp.GetVPPVersion()
			if err != nil {
				log.Warnf("Try [%d/%d] broken vpplink: %v", i, maxRetry, err)
				time.Sleep(retry)
			} else {
				log.Infof("Connected to VPP version %s", version)
				return vpp, nil
			}
		}
	}
	return nil, errors.Errorf("Cannot connect to VPP after 10 tries")
}

func WaitForVppManager() (*config.VppManagerInfo, error) {
	vppManagerInfo := &config.VppManagerInfo{}
	for i := 0; i < 20; i++ {
		dat, err := os.ReadFile(config.VppManagerInfoFile)
		if err == nil {
			err2 := json.Unmarshal(dat, vppManagerInfo)
			if err2 != nil {
				return nil, errors.Errorf("cannot unmarshal vpp manager info file %s", err2)
			} else if vppManagerInfo.Status == config.Ready {
				return vppManagerInfo, nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return nil, errors.Errorf("Vpp manager not ready after 20 tries")
}

func WritePidToFile() error {
	pid := strconv.FormatInt(int64(os.Getpid()), 10)
	return os.WriteFile(config.CalicoVppPidFile, []byte(pid+"\n"), 0400)
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

func IsV6Cidr(cidr *net.IPNet) bool {
	_, bits := cidr.Mask.Size()
	return bits == 128
}

func IsFullyQualified(cidr *net.IPNet) bool {
	ones, bits := cidr.Mask.Size()
	return ones == bits
}

func FullyQualified(addr net.IP) *net.IPNet {
	return &net.IPNet{
		IP:   addr,
		Mask: GetMaxCIDRMask(addr),
	}
}

var (
	ErrNoNodeIPv4 = errors.New("no ip4 address for node")
	ErrNoNodeIPv6 = errors.New("no ip6 address for node")
)

func IsMissingNodeIP(err error) bool {
	if err == nil {
		return false
	}
	cause := errors.Cause(err)
	return cause == ErrNoNodeIPv4 || cause == ErrNoNodeIPv6
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

func MakePath(prefix string, isWithdrawal bool, nodeIPv4 *net.IP, nodeIPv6 *net.IP, vni uint32, asNumber uint32) (*bgpapi.Path, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	masklen, _ := ipNet.Mask.Size()
	var nlri *apb.Any
	if vni != 0 {
		rdAttr, err := apb.New(&bgpapi.RouteDistinguisherTwoOctetASN{
			Admin:    asNumber,
			Assigned: vni,
		})
		if err != nil {
			return nil, err
		}
		nlri, err = apb.New(&bgpapi.LabeledVPNIPAddressPrefix{
			Prefix:    ipNet.IP.String(),
			PrefixLen: uint32(masklen),
			Rd:        rdAttr,
		})
		if err != nil {
			return nil, err
		}
	} else {
		nlri, err = apb.New(&bgpapi.IPAddressPrefix{
			Prefix:    ipNet.IP.String(),
			PrefixLen: uint32(masklen),
		})
		if err != nil {
			return nil, err
		}
	}
	var family *bgpapi.Family
	originAttr, err := apb.New(&bgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	attrs := []*apb.Any{originAttr}

	if ipNet.IP.To4() != nil {
		if nodeIPv4 == nil {
			return nil, ErrNoNodeIPv4
		}
		family = &BgpFamilyUnicastIPv4
		if vni != 0 {
			family = &BgpFamilyUnicastIPv4VPN
		}
		var nhAttr *apb.Any

		if *config.GetCalicoVppFeatureGates().SRv6Enabled {
			if nodeIPv6 == nil {
				return nil, ErrNoNodeIPv6
			}
			nhAttr, err = apb.New(&bgpapi.NextHopAttribute{
				NextHop: nodeIPv6.String(),
			})
		} else {
			nhAttr, err = apb.New(&bgpapi.NextHopAttribute{
				NextHop: nodeIPv4.String(),
			})
		}
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nhAttr)
	} else {
		if nodeIPv6 == nil {
			return nil, ErrNoNodeIPv6
		}
		family = &BgpFamilyUnicastIPv6
		if vni != 0 {
			family = &BgpFamilyUnicastIPv6VPN
		}
		var nlriAttr *apb.Any
		var familySafi bgpapi.Family_Safi
		if vni != 0 {
			familySafi = bgpapi.Family_SAFI_MPLS_VPN
		} else {
			familySafi = bgpapi.Family_SAFI_UNICAST
		}
		nlriAttr, err = apb.New(&bgpapi.MpReachNLRIAttribute{
			NextHops: []string{nodeIPv6.String()},
			Nlris:    []*apb.Any{nlri},
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
		Age:        timestamppb.Now(),
		Family:     family,
	}, nil
}

func MakePathSRv6Tunnel(localSid net.IP, bSid net.IP, nodeIPv6 net.IP, trafficType int, isWithdrawal bool) (*bgpapi.Path, error) {
	originAttr, err := apb.New(&bgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	attrs := []*apb.Any{originAttr}

	var family *bgpapi.Family
	var nodeIP = nodeIPv6
	var epbs = &bgpapi.SRv6EndPointBehavior{}
	family = &BgpFamilySRv6IPv6
	if trafficType == 4 {
		epbs.Behavior = bgpapi.SRv6Behavior_END_DT4
	} else {
		epbs.Behavior = bgpapi.SRv6Behavior_END_DT6
	}

	nlrisr, err := apb.New(&bgpapi.SRPolicyNLRI{
		Length:   192,
		Endpoint: nodeIP,
	})

	if err != nil {
		return nil, err
	}
	nhAttr, err := apb.New(&bgpapi.NextHopAttribute{
		NextHop: nodeIP.String(),
	})
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, nhAttr)

	sid, err := apb.New(&bgpapi.SRBindingSID{
		SFlag: true,
		IFlag: false,
		Sid:   bSid,
	})

	if err != nil {
		return nil, err
	}
	bsid, err := apb.New(&bgpapi.TunnelEncapSubTLVSRBindingSID{
		Bsid: sid,
	})
	if err != nil {
		return nil, err
	}

	segment, err := apb.New(&bgpapi.SegmentTypeB{
		Flags:                     &bgpapi.SegmentFlags{SFlag: true},
		Sid:                       localSid,
		EndpointBehaviorStructure: epbs,
	})
	if err != nil {
		return nil, err
	}
	seglist, err := apb.New(&bgpapi.TunnelEncapSubTLVSRSegmentList{
		Weight: &bgpapi.SRWeight{
			Flags:  0,
			Weight: 12,
		},
		Segments: []*apb.Any{segment},
	})
	if err != nil {
		return nil, err
	}
	pref, err := apb.New(&bgpapi.TunnelEncapSubTLVSRPreference{
		Flags:      0,
		Preference: 11,
	})
	if err != nil {
		return nil, err
	}

	pri, err := apb.New(&bgpapi.TunnelEncapSubTLVSRPriority{
		Priority: 10,
	})
	if err != nil {
		return nil, err
	}
	// Tunnel Encapsulation attribute for SR Policy
	tun, err := apb.New(&bgpapi.TunnelEncapAttribute{
		Tlvs: []*bgpapi.TunnelEncapTLV{
			{
				Type: 15,
				Tlvs: []*apb.Any{bsid, seglist, pref, pri},
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
		Age:        timestamppb.Now(),
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

func GetIPNetChangeType(old, new *net.IPNet) ChangeType {
	var oldStr, newStr string
	if old != nil {
		oldStr = old.IP.String()
	}
	if new != nil {
		newStr = new.IP.String()
	}
	return GetStringChangeType(oldStr, newStr)
}

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

// SRv6Tunnel contains info needed to create all SRv6 tunnel components (Steering, Policy, Localsids)
type SRv6Tunnel struct {
	Dst      net.IP
	Bsid     net.IP
	Policy   *types.SrPolicy
	Sid      net.IP
	Behavior uint8
	Priority uint32
}

func GetBGPSpecAddresses(nodeBGPSpec *LocalNodeSpec) (ip4 *net.IP, ip6 *net.IP) {
	if nodeBGPSpec.IPv4Address != nil {
		ip4 = &nodeBGPSpec.IPv4Address.IP
	}
	if nodeBGPSpec.IPv6Address != nil {
		ip6 = &nodeBGPSpec.IPv6Address.IP
	}
	return
}

func FormatBGPConfiguration(conf *calicov3.BGPConfigurationSpec) string {
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
	if config.GetCalicoVppIpsec().IpsecNbAsyncCryptoThread > 0 {
		nDataThreads = nVppWorkers - config.GetCalicoVppIpsec().IpsecNbAsyncCryptoThread
		if nDataThreads <= 0 {
			log.Errorf("Couldn't fulfill request [crypto=%d total=%d]", config.GetCalicoVppIpsec().IpsecNbAsyncCryptoThread, nVppWorkers)
			nDataThreads = nVppWorkers
		}
		log.Infof("Using ipsec workers [data=%d crypto=%d]", nDataThreads, nVppWorkers-nDataThreads)

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
