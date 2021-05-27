package types

import (
	"fmt"

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/sr"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/sr_types"
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

func ToVppSrBehavior(behavior SrBehavior) sr_types.SrBehavior {
	return sr_types.SrBehavior(behavior)
}
func FromVppSrBehavior(behavior sr_types.SrBehavior) SrBehavior {
	return SrBehavior(behavior)
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

	return fmt.Sprintf("Bsid: %s, IsSpray: %v, IsEncap: %v, FibTable: %d",
		p.Bsid, p.IsSpray, p.IsEncap, p.FibTable)
}

// Srv6SidList definition
type Srv6SidList struct {
	NumSids uint8
	Weight  uint32
	Sids    [16]ip_types.IP6Address
}

func (s *Srv6SidList) String() string {
	return fmt.Sprintf("NumSids: %d, Weight: %d, Sids: %s",
		s.NumSids, s.Weight, s.Sids)
}

type SrSteer struct {
	TrafficType sr_types.SrSteer
	FibTable    uint32
	Prefix      ip_types.Prefix
	SwIfIndex   uint32
	Bsid        ip_types.IP6Address
}

func (s *SrSteer) String() string {
	return fmt.Sprintf("TrafficType: %d, FibTable: %d, Prefix: %s, SwIfIndex: %d, Bsid: %d",
		s.TrafficType, s.FibTable, s.Prefix.String(), s.SwIfIndex, s.Bsid)
}
