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
	"bytes"
	"fmt"
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/gso"
	interfaces "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_neighbor"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/punt"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/tapv2"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

const (
	INVALID_SW_IF_INDEX = ^uint32(0)
)

type NamespaceNotFound error

func (v *VppLink) SetInterfaceMtu(swIfIndex uint32, mtu int) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	mtus := make([]uint32, 4)
	mtus[interface_types.MTU_PROTO_API_L3] = uint32(mtu)
	response := &interfaces.SwInterfaceSetMtuReply{}
	request := &interfaces.SwInterfaceSetMtu{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Mtu:       mtus,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceSetMtu failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceSetMtu failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *VppLink) SetInterfaceRxMode(swIfIndex uint32, queueID uint32, mode types.RxMode) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &interfaces.SwInterfaceSetRxModeReply{}
	request := &interfaces.SwInterfaceSetRxMode{
		SwIfIndex:    interface_types.InterfaceIndex(swIfIndex),
		QueueIDValid: queueID != types.AllQueues,
		QueueID:      queueID,
		Mode:         interface_types.RxMode(mode),
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SetInterfaceRxMode failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SetInterfaceRxMode failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *VppLink) SetInterfaceMacAddress(swIfIndex uint32, mac *net.HardwareAddr) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &interfaces.SwInterfaceSetMacAddressReply{}
	request := &interfaces.SwInterfaceSetMacAddress{
		SwIfIndex:  interface_types.InterfaceIndex(swIfIndex),
		MacAddress: types.ToVppMacAddress(mac),
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceSetMacAddress failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceSetMacAddress failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *VppLink) SetInterfaceVRF(swIfIndex, vrfIndex uint32) error {
	err := v.SetInterfaceVRFAf(swIfIndex, vrfIndex, false)
	if err != nil {
		return err
	}
	err = v.SetInterfaceVRFAf(swIfIndex, vrfIndex, true)
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) SetInterfaceVRFAf(swIfIndex, vrfIndex uint32, isIP6 bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &interfaces.SwInterfaceSetTableReply{}
	request := &interfaces.SwInterfaceSetTable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIPv6:    isIP6,
		VrfID:     vrfIndex,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceSetTable failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceSetTable failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func defaultIntTo(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	} else {
		return value
	}
}

func (v *VppLink) CreateTapV2(tap *types.TapV2) (swIfIndex uint32, err error) {
	response := &tapv2.TapCreateV2Reply{}
	request := &tapv2.TapCreateV2{
		ID:                   ^uint32(0),
		Tag:                  tap.Tag,
		TapFlags:             tapv2.TapFlags(tap.Flags),
		NumRxQueues:          uint8(defaultIntTo(tap.NumRxQueues, 1)),
		NumTxQueuesPerWorker: uint8(defaultIntTo(tap.NumTxQueues, 1)),
		TxRingSz:             uint16(defaultIntTo(tap.TxQueueSize, 1024)),
		RxRingSz:             uint16(defaultIntTo(tap.RxQueueSize, 1024)),
		HostMtuSize:          uint32(tap.HostMtu),
		HostMtuSet:           bool(tap.HostMtu != 0),
	}
	if tap.HardwareAddr != nil {
		request.MacAddress = types.ToVppMacAddress(tap.HardwareAddr)
	} else {
		request.UseRandomMac = true
	}

	if tap.TxQueueSize > 0 {
		request.TxRingSz = uint16(tap.TxQueueSize)
	}
	if tap.RxQueueSize > 0 {
		request.RxRingSz = uint16(tap.RxQueueSize)
	}
	if len(tap.HostNamespace) > 64 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("HostNamespace should be less than 64 characters")
	}
	if tap.HostNamespace != "" {
		request.HostNamespaceSet = true
		request.HostNamespace = tap.HostNamespace
	}
	if len(tap.HostInterfaceName) > 64 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("HostInterfaceName should be less than 64 characters")
	}
	if tap.HostInterfaceName != "" {
		request.HostIfName = tap.HostInterfaceName
		request.HostIfNameSet = true
	}
	if tap.HostMacAddress != nil {
		request.HostMacAddr = types.ToVppMacAddress(&tap.HostMacAddress)
		request.HostMacAddrSet = true
	}
	v.lock.Lock()
	err = v.ch.SendRequest(request).ReceiveReply(response)
	v.lock.Unlock()

	if err != nil {
		return INVALID_SW_IF_INDEX, errors.Wrap(err, "Tap creation request failed")
	} else if response.Retval == -12 {
		return INVALID_SW_IF_INDEX, nil
	} else if response.Retval != 0 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("Tap creation failed (retval %d). Request: %+v", response.Retval, request)
	}

	return uint32(response.SwIfIndex), err
}

func (v *VppLink) CreateOrAttachTapV2(tap *types.TapV2) (swIfIndex uint32, err error) {
	tap.Flags |= types.TapFlagPersist | types.TapFlagAttach
	swIfIndex, err = v.CreateTapV2(tap)
	if err == nil && swIfIndex == INVALID_SW_IF_INDEX {
		tap.Flags &= ^types.TapFlagAttach
		return v.CreateTapV2(tap)
	}
	return swIfIndex, err
}

func (v *VppLink) addDelInterfaceAddress(swIfIndex uint32, addr *net.IPNet, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	request := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     isAdd,
		Prefix:    types.ToVppAddressWithPrefix(addr),
	}
	response := &interfaces.SwInterfaceAddDelAddressReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Adding IP address failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *VppLink) DelInterfaceAddress(swIfIndex uint32, addr *net.IPNet) error {
	return v.addDelInterfaceAddress(swIfIndex, addr, false)
}

func (v *VppLink) AddInterfaceAddress(swIfIndex uint32, addr *net.IPNet) error {
	return v.addDelInterfaceAddress(swIfIndex, addr, true)
}

func (v *VppLink) enableDisableInterfaceIP6(swIfIndex uint32, enable bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &vppip.SwInterfaceIP6EnableDisable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Enable:    enable,
	}
	response := &vppip.SwInterfaceIP6EnableDisableReply{}
	return v.ch.SendRequest(request).ReceiveReply(response)
}

func (v *VppLink) DisableInterfaceIP6(swIfIndex uint32) error {
	return v.enableDisableInterfaceIP6(swIfIndex, false)
}

func (v *VppLink) EnableInterfaceIP6(swIfIndex uint32) error {
	return v.enableDisableInterfaceIP6(swIfIndex, true)
}

func (v *VppLink) SearchInterfaceWithTag(tag string) (err error, swIfIndex uint32) {
	v.lock.Lock()
	defer v.lock.Unlock()

	swIfIndex = INVALID_SW_IF_INDEX
	request := &interfaces.SwInterfaceDump{}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.log.Errorf("error listing VPP interfaces: %v", err)
			return err, INVALID_SW_IF_INDEX
		}
		if stop {
			break
		}
		intfTag := string(bytes.Trim([]byte(response.Tag), "\x00"))
		v.log.Debugf("found interface %d, tag: %s (len %d)", response.SwIfIndex, intfTag, len(intfTag))
		if intfTag == tag {
			swIfIndex = uint32(response.SwIfIndex)
		}
	}
	if swIfIndex == INVALID_SW_IF_INDEX {
		return nil, INVALID_SW_IF_INDEX
	}
	return nil, swIfIndex
}

func (v *VppLink) SearchInterfaceWithName(name string) (err error, swIfIndex uint32) {
	v.lock.Lock()
	defer v.lock.Unlock()

	swIfIndex = INVALID_SW_IF_INDEX
	request := &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(INVALID_SW_IF_INDEX),
		// TODO: filter by name with NameFilter
	}
	reqCtx := v.ch.SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(response)
		if err != nil {
			v.log.Errorf("SwInterfaceDump failed: %v", err)
			return err, INVALID_SW_IF_INDEX
		}
		if stop {
			break
		}
		interfaceName := string(bytes.Trim([]byte(response.InterfaceName), "\x00"))
		v.log.Debugf("Found interface: %s", interfaceName)
		if interfaceName == name {
			swIfIndex = uint32(response.SwIfIndex)
		}

	}
	if swIfIndex == INVALID_SW_IF_INDEX {
		v.log.Errorf("Interface %s not found", name)
		return errors.New("Interface not found"), INVALID_SW_IF_INDEX
	}
	return nil, swIfIndex
}

func (v *VppLink) GetInterfaceDetails(swIfIndex uint32) (i *types.VppInterfaceDetails, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.log.Errorf("error listing VPP interfaces: %v", err)
			return nil, err
		}
		if stop {
			break
		}
		if uint32(response.SwIfIndex) != swIfIndex {
			v.log.Debugf("Got interface that doesn't match filter, fix vpp")
			continue
		}
		v.log.Debugf("found interface %d", response.SwIfIndex)
		i = &types.VppInterfaceDetails{
			SwIfIndex: uint32(response.SwIfIndex),
			IsUp:      response.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP > 0,
			Name:      response.InterfaceName,
			Tag:       response.Tag,
			Type:      response.InterfaceDevType,
		}
	}
	if i == nil {
		return nil, errors.New("Interface not found")
	}
	return i, nil
}

func (v *VppLink) interfaceAdminUpDown(swIfIndex uint32, up bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	var f interface_types.IfStatusFlags = 0
	if up {
		f |= interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	}
	// Set interface down
	request := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Flags:     f,
	}
	response := &interfaces.SwInterfaceSetFlagsReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "setting interface up/down failed")
	}
	return nil
}

func (v *VppLink) InterfaceAdminDown(swIfIndex uint32) error {
	return v.interfaceAdminUpDown(swIfIndex, false)
}

func (v *VppLink) InterfaceAdminUp(swIfIndex uint32) error {
	return v.interfaceAdminUpDown(swIfIndex, true)
}

func (v *VppLink) GetInterfaceNeighbors(swIfIndex uint32, isIPv6 bool) (err error, neighbors []types.Neighbor) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &ip_neighbor.IPNeighborDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Af:        ip_types.ADDRESS_IP4,
	}
	if isIPv6 {
		request.Af = ip_types.ADDRESS_IP6
	}
	response := &ip_neighbor.IPNeighborDetails{}
	stream := v.ch.SendMultiRequest(request)
	for {
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.log.Errorf("error listing VPP neighbors: %v", err)
			return err, nil
		}
		if stop {
			return nil, neighbors
		}
		vppNeighbor := response.Neighbor
		neighbors = append(neighbors, types.Neighbor{
			SwIfIndex:    uint32(vppNeighbor.SwIfIndex),
			Flags:        types.FromVppNeighborFlags(vppNeighbor.Flags),
			IP:           types.FromVppAddress(vppNeighbor.IPAddress),
			HardwareAddr: types.FromVppMacAddress(vppNeighbor.MacAddress),
		})
	}
}

func (v *VppLink) DelTap(swIfIndex uint32) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &tapv2.TapDeleteV2{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	response := &tapv2.TapDeleteV2Reply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "failed to delete tap from VPP")
	}
	return nil
}

func (v *VppLink) interfaceSetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32, isAdd bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &interfaces.SwInterfaceSetUnnumbered{
		SwIfIndex:           interface_types.InterfaceIndex(swIfIndex),
		UnnumberedSwIfIndex: interface_types.InterfaceIndex(unnumberedSwIfIndex),
		IsAdd:               isAdd,
	}
	response := &interfaces.SwInterfaceSetUnnumberedReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "setting interface unnumbered failed %d -> %d", unnumberedSwIfIndex, swIfIndex)
	}
	return nil
}

func (v *VppLink) AddrList(swIfIndex uint32, isv6 bool) (addresses []types.IfAddress, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &vppip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIPv6:    isv6,
	}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &vppip.IPAddressDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return addresses, errors.Wrapf(err, "error listing VPP interfaces addresses")
		}
		if stop {
			break
		}
		address := types.IfAddress{
			SwIfIndex: uint32(response.SwIfIndex),
			IPNet:     *types.FromVppAddressWithPrefix(response.Prefix),
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func (v *VppLink) InterfaceSetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32) error {
	return v.interfaceSetUnnumbered(unnumberedSwIfIndex, swIfIndex, true)
}

func (v *VppLink) InterfaceUnsetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32) error {
	return v.interfaceSetUnnumbered(unnumberedSwIfIndex, swIfIndex, false)
}

func (v *VppLink) PuntRedirect(sourceSwIfIndex, destSwIfIndex uint32, nh net.IP) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	request := &vppip.IPPuntRedirect{
		Punt: vppip.PuntRedirect{
			RxSwIfIndex: interface_types.InterfaceIndex(sourceSwIfIndex),
			TxSwIfIndex: interface_types.InterfaceIndex(destSwIfIndex),
			Nh:          types.ToVppAddress(nh),
		},
		IsAdd: true,
	}
	response := &vppip.IPPuntRedirectReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set punt in VPP: %v %d", err, response.Retval)
	}
	return nil
}

// PuntL4 configures L4 punt for a given address family and protocol. port = ~0 means all ports
func (v *VppLink) PuntL4(proto types.IPProto, port uint16, isIPv6 bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	request := &punt.SetPunt{
		Punt: punt.Punt{
			Type: punt.PUNT_API_TYPE_L4,
			Punt: punt.PuntUnionL4(punt.PuntL4{
				Af:       types.ToVppAddressFamily(isIPv6),
				Protocol: types.ToVppIPProto(proto),
				Port:     port,
			}),
		},
		IsAdd: true,
	}
	response := &punt.SetPuntReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set punt in VPP: %v %d", err, response.Retval)
	}
	return nil
}

func (v *VppLink) PuntAllL4(isIPv6 bool) (err error) {
	err = v.PuntL4(types.TCP, 0xffff, isIPv6)
	if err != nil {
		return err
	}
	err = v.PuntL4(types.UDP, 0xffff, isIPv6)
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) enableDisableGso(swIfIndex uint32, enable bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	request := &gso.FeatureGsoEnableDisable{
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		EnableDisable: enable,
	}
	response := &gso.FeatureGsoEnableDisableReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot configure gso: %v %d", err, response.Retval)
	}
	return nil
}

func (v *VppLink) setInterfacePromiscuous(swIfIndex uint32, promiscOn bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()
	request := &interfaces.SwInterfaceSetPromisc{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		PromiscOn: promiscOn,
	}
	response := &interfaces.SwInterfaceSetPromiscReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot configure gso: %v %d", err, response.Retval)
	}
	return nil
}

func (v *VppLink) SetPromiscOn(swIfIndex uint32) error {
	return v.setInterfacePromiscuous(swIfIndex, true)
}

func (v *VppLink) SetPromiscOff(swIfIndex uint32) error {
	return v.setInterfacePromiscuous(swIfIndex, false)
}

func (v *VppLink) EnableGSOFeature(swIfIndex uint32) error {
	return v.enableDisableGso(swIfIndex, true)
}

func (v *VppLink) DisableGSOFeature(swIfIndex uint32) error {
	return v.enableDisableGso(swIfIndex, false)
}

func (v *VppLink) SetInterfaceRxPlacement(swIfIndex, queue, worker uint32, main bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &interfaces.SwInterfaceSetRxPlacement{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		QueueID:   queue,
		WorkerID:  worker,
		IsMain:    main,
	}
	response := &interfaces.SwInterfaceSetRxPlacementReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set interface rx placement: %v %d", err, response.Retval)
	}
	return nil
}
