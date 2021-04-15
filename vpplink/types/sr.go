package types

import (
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/sr_types"
)

// SrLocalsid definition
type SrLocalsid struct {
	Localsid  ip_types.IP6Address
	EndPsp    bool
	Behavior  sr_types.SrBehavior
	SwIfIndex interface_types.InterfaceIndex
	VlanIndex uint32
	FibTable  uint32
	NhAddr    ip_types.Address
}

// SrPolicy definition
type SrPolicy struct {
	Bsid        ip_types.IP6Address
	IsSpray     bool
	IsEncap     bool
	FibTable    uint32
	NumSidLists uint8
	SidLists    []Srv6SidList
}

// Srv6SidList definition
type Srv6SidList struct {
	NumSids uint8
	Weight  uint32
	SlIndex uint32
	Sids    [16]ip_types.IP6Address
}
