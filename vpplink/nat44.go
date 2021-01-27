// Copyright (C) 2019 Cisco Systems Inc.
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

package vpplink

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	nat "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/nat44"
	nat_types "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/nat_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) EnableNatForwarding() (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44ForwardingEnableDisableReply{}
	request := &nat.Nat44ForwardingEnableDisable{
		Enable: true,
	}
	v.log.Debug("Enabling NAT44 forwarding")
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "NAT44 forwarding enable failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("NAT44 forwarding enable failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) addDelNat44Address(isAdd bool, address net.IP) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44AddDelAddressRangeReply{}
	request := &nat.Nat44AddDelAddressRange{
		FirstIPAddress: types.ToVppIP4Address(address),
		LastIPAddress:  types.ToVppIP4Address(address),
		VrfID:          0,
		IsAdd:          isAdd,
		Flags:          nat_types.NAT_IS_NONE,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 address add failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 address add failed with retval %d", response.Retval)
	}
	return nil
}

func (v *VppLink) AddNat44InterfaceAddress(swIfIndex uint32, flags types.NatFlags) error {
	return v.addDelNat44InterfaceAddress(true, swIfIndex, flags)
}

func (v *VppLink) DelNat44InterfaceAddress(swIfIndex uint32, flags types.NatFlags) error {
	return v.addDelNat44InterfaceAddress(false, swIfIndex, flags)
}

func (v *VppLink) addDelNat44InterfaceAddress(isAdd bool, swIfIndex uint32, flags types.NatFlags) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44AddDelInterfaceAddrReply{}
	request := &nat.Nat44AddDelInterfaceAddr{
		IsAdd:     isAdd,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Flags:     types.ToVppNatConfigFlags(flags),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 addDel interface address failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 addDel interface address failed: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) AddNat44Address(address net.IP) error {
	return v.addDelNat44Address(true, address)
}

func (v *VppLink) DelNat44Address(address net.IP) error {
	return v.addDelNat44Address(false, address)
}

func (v *VppLink) addDelNat44Interface(isAdd bool, flags types.NatFlags, swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44InterfaceAddDelFeatureReply{}
	request := &nat.Nat44InterfaceAddDelFeature{
		IsAdd:     isAdd,
		Flags:     types.ToVppNatConfigFlags(flags),
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 addDel interface failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 addDel interface failed: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) AddNat44InsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(true, types.NatInside, swIfIndex)
}

func (v *VppLink) AddNat44OutsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(true, types.NatOutside, swIfIndex)
}

func (v *VppLink) DelNat44InsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(false, types.NatInside, swIfIndex)
}

func (v *VppLink) DelNat44OutsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(false, types.NatOutside, swIfIndex)
}

func (v *VppLink) getLBLocals(entry *types.Nat44Entry) (locals []nat.Nat44LbAddrPort) {
	for _, ip := range entry.BackendIPs {
		v.log.Debugf("Adding local %s:%d", ip, entry.BackendPort)
		locals = append(locals, nat.Nat44LbAddrPort{
			Addr:        types.ToVppIP4Address(ip),
			Port:        uint16(entry.BackendPort),
			Probability: uint8(10),
		})
	}
	return locals
}

func (v *VppLink) addDelNat44LBStaticMapping(isAdd bool, entry *types.Nat44Entry) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	locals := v.getLBLocals(entry)
	response := &nat.Nat44AddDelLbStaticMappingReply{}
	request := &nat.Nat44AddDelLbStaticMapping{
		IsAdd:        isAdd,
		Flags:        nat_types.NAT_IS_SELF_TWICE_NAT | nat_types.NAT_IS_OUT2IN_ONLY,
		ExternalAddr: types.ToVppIP4Address(entry.ServiceIP),
		ExternalPort: uint16(entry.ServicePort),
		Protocol:     uint8(types.ToVppIPProto(entry.Protocol)),
		Locals:       locals,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 add LB static failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 add LB static failed: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) AddNat44LBStaticMapping(entry *types.Nat44Entry) error {
	return v.addDelNat44LBStaticMapping(true, entry)
}

func (v *VppLink) DelNat44LBStaticMapping(entry *types.Nat44Entry) error {
	return v.addDelNat44LBStaticMapping(false, entry)
}

func (v *VppLink) addDelNat44StaticMapping(isAdd bool, entry *types.Nat44Entry) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44AddDelStaticMappingReply{}
	request := &nat.Nat44AddDelStaticMapping{
		IsAdd:             isAdd,
		Flags:             nat_types.NAT_IS_SELF_TWICE_NAT | nat_types.NAT_IS_OUT2IN_ONLY,
		LocalIPAddress:    types.ToVppIP4Address(entry.BackendIPs[0]),
		ExternalIPAddress: types.ToVppIP4Address(entry.ServiceIP),
		Protocol:          uint8(types.ToVppIPProto(entry.Protocol)),
		LocalPort:         uint16(entry.BackendPort),
		ExternalPort:      uint16(entry.ServicePort),
		ExternalSwIfIndex: 0xffffffff,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 static mapping failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 add LB static failed: %d", response.Retval)
	}
	return nil
}

func (v *VppLink) AddNat44StaticMapping(entry *types.Nat44Entry) error {
	return v.addDelNat44StaticMapping(true, entry)
}

func (v *VppLink) DelNat44StaticMapping(entry *types.Nat44Entry) error {
	return v.addDelNat44StaticMapping(false, entry)
}

func (v *VppLink) AddNat44LB(entry *types.Nat44Entry) error {
	if len(entry.BackendIPs) == 0 {
		return nil
	}
	if len(entry.BackendIPs) == 1 {
		return v.AddNat44StaticMapping(entry)
	}
	return v.AddNat44LBStaticMapping(entry)
}

func (v *VppLink) DelNat44LB(entry *types.Nat44Entry) error {
	if len(entry.BackendIPs) == 0 {
		return nil
	}
	if len(entry.BackendIPs) == 1 {
		return v.DelNat44StaticMapping(entry)
	}
	return v.DelNat44LBStaticMapping(entry)
}
