package types

import (
	"fmt"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/sr"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/sr_types"
)

type SrBehavior uint8

const (
	SrBehaviorEND    SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_END)
	SrBehaviorX      SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_X)
	SrBehaviorT      SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_T)
	SrBehaviorDFIRST SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_D_FIRST)
	SrBehaviorDX2    SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_DX2)
	SrBehaviorDX6    SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_DX6)
	SrBehaviorDX4    SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_DX4)
	SrBehaviorDT6    SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_DT6)
	SrBehaviorDT4    SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_DT4)
	SrBehaviorLAST   SrBehavior = SrBehavior(sr_types.SR_BEHAVIOR_API_LAST)
)

var (
	SrBehaviorVPP_GoBGP = map[uint8]bgpapi.SRv6Behavior{
		1: bgpapi.SRv6Behavior_END,
		2: bgpapi.SRv6Behavior_ENDX,
		3: bgpapi.SRv6Behavior_ENDT,
		5: bgpapi.SRv6Behavior_END_DX2,
		6: bgpapi.SRv6Behavior_END_DX6,
		7: bgpapi.SRv6Behavior_END_DX4,
		8: bgpapi.SRv6Behavior_END_DT6,
		9: bgpapi.SRv6Behavior_END_DT4,
	}
	SrBehaviorGoBGP_VPP = map[bgpapi.SRv6Behavior]uint8{
		bgpapi.SRv6Behavior_END:     1,
		bgpapi.SRv6Behavior_ENDX:    2,
		bgpapi.SRv6Behavior_ENDT:    3,
		bgpapi.SRv6Behavior_END_DX2: 5,
		bgpapi.SRv6Behavior_END_DX6: 6,
		bgpapi.SRv6Behavior_END_DX4: 7,
		bgpapi.SRv6Behavior_END_DT6: 8,
		bgpapi.SRv6Behavior_END_DT4: 9,
	}
)

func ToVppSrBehavior(behavior SrBehavior) sr_types.SrBehavior {
	return sr_types.SrBehavior(behavior)
}
func FromVppSrBehavior(behavior sr_types.SrBehavior) SrBehavior {
	return SrBehavior(behavior)
}

func FromGoBGPSrBehavior(behavior uint8) SrBehavior {
	var result = SrBehaviorGoBGP_VPP[bgpapi.SRv6Behavior(behavior)]
	return SrBehavior(result)
}

// SrLocalsid definition
type SrLocalsid struct {
	Localsid  ip_types.IP6Address
	EndPsp    bool
	Behavior  SrBehavior
	SwIfIndex interface_types.InterfaceIndex
	VlanIndex uint32
	FibTable  uint32
	NhAddr    ip_types.Address
}

func (l *SrLocalsid) SetBehavior(code uint8) {
	l.Behavior = SrBehavior(code)
}

func (l *SrLocalsid) CompareBehaviorTo(behavior uint8) bool {
	return uint8(l.Behavior) == behavior
}

func (l *SrLocalsid) String() (policy string) {
	return fmt.Sprintf("Localsid: %s, EndPsp: %v,  Behavior: %d, SwIfIndex: %d, VlanIndex: %d, FibTable: %d, NhAddr: %s",
		l.Localsid, l.EndPsp, uint8(l.Behavior), l.SwIfIndex, l.VlanIndex, l.FibTable, l.NhAddr.String())
}

// SrPolicy definition
type SrPolicy struct {
	Bsid     ip_types.IP6Address
	IsSpray  bool
	IsEncap  bool
	FibTable uint32
	SidLists []Srv6SidList
}

func (p *SrPolicy) FromVPP(response *sr.SrPoliciesDetails) {
	p.Bsid = response.Bsid
	p.IsSpray = response.IsSpray
	p.IsEncap = response.IsEncap
	p.FibTable = response.FibTable
	sidLists := []Srv6SidList{}
	for _, sl := range response.SidLists {
		sidLists = append(sidLists, Srv6SidList{
			NumSids: sl.NumSids,
			Weight:  sl.Weight,
			Sids:    sl.Sids,
		})
	}
	p.SidLists = sidLists
}

func (p *SrPolicy) String() (policy string) {

	policy = fmt.Sprintf("Bsid: %s, IsSpray: %v, IsEncap: %v, FibTable: %d, SidLists: [",
		p.Bsid, p.IsSpray, p.IsEncap, p.FibTable)
	for _, sidList := range p.SidLists {
		policy += sidList.String()
	}
	policy += "]"
	return policy
}

// Srv6SidList definition
type Srv6SidList struct {
	NumSids uint8
	Weight  uint32
	Sids    [16]ip_types.IP6Address
}

func (s *Srv6SidList) String() string {
	return fmt.Sprintf("{NumSids: %d, Weight: %d, Sids: %s}",
		s.NumSids, s.Weight, s.Sids)
}

type SrSteerTrafficType uint8

const (
	SR_STEER_L2   SrSteerTrafficType = SrSteerTrafficType(sr_types.SR_STEER_API_L2)
	SR_STEER_IPV4 SrSteerTrafficType = SrSteerTrafficType(sr_types.SR_STEER_API_IPV4)
	SR_STEER_IPV6 SrSteerTrafficType = SrSteerTrafficType(sr_types.SR_STEER_API_IPV6)
)

func ToVppSrSteerTrafficType(trafficType SrSteerTrafficType) sr_types.SrSteer {
	return sr_types.SrSteer(trafficType)
}
func FromVppSrSteerTrafficType(trafficType sr_types.SrSteer) SrSteerTrafficType {
	return SrSteerTrafficType(trafficType)
}

type SrSteer struct {
	TrafficType SrSteerTrafficType
	FibTable    uint32
	Prefix      ip_types.Prefix
	SwIfIndex   uint32
	Bsid        ip_types.IP6Address
}

func (s *SrSteer) String() string {
	return fmt.Sprintf("TrafficType: %d, FibTable: %d, Prefix: %s, SwIfIndex: %d, Bsid: %s",
		s.TrafficType, s.FibTable, s.Prefix.String(), s.SwIfIndex, s.Bsid.String())
}
