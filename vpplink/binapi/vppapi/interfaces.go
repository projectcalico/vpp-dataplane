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

package vppapi

import (
    "bytes"
    "fmt"
	"github.com/pkg/errors"
	"net"
	"strings"

    types2 "git.fd.io/govpp.git/api/v0"

	interfaces "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface"
	vppip "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip"

    "github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/gso"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_neighbor"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/tapv2"
)

func defaultIntTo(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	} else {
		return value
	}
}

func (v *Vpp) CreateLoopback(hwAddr *net.HardwareAddr) (swIfIndex uint32, err error) {
	v.Lock()
	defer v.Unlock()
	request := &interfaces.CreateLoopback{
		MacAddress: ToVppMacAddress(hwAddr),
	}
	response := &interfaces.CreateLoopbackReply{}
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return 0, errors.Wrapf(err, "Error adding loopback: req %+v reply %+v", request, response)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *Vpp) DeleteLoopback(iface *types2.Interface) (err error) {
	v.Lock()
	defer v.Unlock()
	request := &interfaces.DeleteLoopback{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
	}
	response := &interfaces.DeleteLoopbackReply{}
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return errors.Wrapf(err, "Error deleting loopback: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *Vpp) CreateTapV2(tap *types2.TapInterface) (swIfIndex uint32, err error) {
	response := &tapv2.TapCreateV3Reply{}
	request := &tapv2.TapCreateV3{
		ID:          ^uint32(0),
		Tag:         tap.Tag,
		TapFlags:    tapv2.TapFlags(tap.Flags),
		NumRxQueues: uint16(defaultIntTo(tap.NumRxQueues, 1)),
		NumTxQueues: uint16(defaultIntTo(tap.NumTxQueues, 1)),
		TxRingSz:    uint16(defaultIntTo(tap.TxQueueSize, types2.DefaultQueueSize)),
		RxRingSz:    uint16(defaultIntTo(tap.RxQueueSize, types2.DefaultQueueSize)),
		HostMtuSize: uint32(tap.HostMtu),
		HostMtuSet:  tap.HostMtu != 0,
	}
	if tap.HardwareAddr != nil {
		request.MacAddress = ToVppMacAddress(tap.HardwareAddr)
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
		return InvalidSwIfIndex, fmt.Errorf("HostNamespace should be less than 64 characters")
	}
	if tap.HostNamespace != "" {
		request.HostNamespaceSet = true
		request.HostNamespace = tap.HostNamespace
	}
	if len(tap.HostInterfaceName) > 64 {
		return InvalidSwIfIndex, fmt.Errorf("HostInterfaceName should be less than 64 characters")
	}
	if tap.HostInterfaceName != "" {
		request.HostIfName = tap.HostInterfaceName
		request.HostIfNameSet = true
	}
	if tap.HostMacAddress != nil {
		request.HostMacAddr = ToVppMacAddress(&tap.HostMacAddress)
		request.HostMacAddrSet = true
	}
	v.Lock()
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	v.Unlock()

	if err != nil {
		return InvalidSwIfIndex, errors.Wrap(err, "Tap creation request failed")
	} else if response.Retval == -12 {
		return InvalidSwIfIndex, nil
	} else if response.Retval != 0 {
		return InvalidSwIfIndex, fmt.Errorf("tap creation failed (retval %d). Request: %+v", response.Retval, request)
	}

	return uint32(response.SwIfIndex), err
}

func (v *Vpp) CreateOrAttachTapV2(tap *types2.TapInterface) (swIfIndex uint32, err error) {
	tap.Flags |= types2.TapFlagPersist | types2.TapFlagAttach
	swIfIndex, err = v.CreateTapV2(tap)
	if err == nil && swIfIndex == InvalidSwIfIndex {
		tap.Flags &= ^types2.TapFlagAttach
		return v.CreateTapV2(tap)
	}
	return swIfIndex, err
}

func (v *Vpp) DelTap(iface *types2.Interface) error {
	v.Lock()
	defer v.Unlock()

	request := &tapv2.TapDeleteV2{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
	}
	response := &tapv2.TapDeleteV2Reply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "failed to delete tap from VPP")
	}
	return nil
}

func (v *Vpp) SearchInterfaceWithName(name string) (err error, swIfIndex uint32) {
	v.Lock()
	defer v.Unlock()

	swIfIndex = InvalidSwIfIndex
	request := &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(InvalidSwIfIndex),
		/* TODO: filter by name with NameFilter
		NameFilter: name,
		NameFilterValid: true,
		*/
	}
	reqCtx := v.GetChannel().SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(response)
		if err != nil {
			v.GetLog().Errorf("SwInterfaceDump failed: %v", err)
			return err, InvalidSwIfIndex
		}
		if stop {
			break
		}
		interfaceName := string(bytes.Trim([]byte(response.InterfaceName), "\x00"))
		v.GetLog().Debugf("Found interface: %s", interfaceName)
		if interfaceName == name {
			swIfIndex = uint32(response.SwIfIndex)
		}

	}
	if swIfIndex == InvalidSwIfIndex {
		v.GetLog().Errorf("Interface %s not found", name)
		return errors.New("Interface not found"), InvalidSwIfIndex
	}
	return nil, swIfIndex
}

func (v *Vpp) searchInterfaceWithTagOrTagPrefix(tag string, prefix bool) (err error, swIfIndex uint32, swIfIndexes map[string]uint32) {
	v.Lock()
	defer v.Unlock()

	swIfIndex = InvalidSwIfIndex
	swIfIndexes = make(map[string]uint32)
	request := &interfaces.SwInterfaceDump{}
	stream := v.GetChannel().SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.GetLog().Errorf("error listing VPP interfaces: %v", err)
			return err, InvalidSwIfIndex, swIfIndexes
		}
		if stop {
			break
		}
		intfTag := string(bytes.Trim([]byte(response.Tag), "\x00"))
		v.GetLog().Debugf("found interface %d, tag: %s (len %d)", response.SwIfIndex, intfTag, len(intfTag))
		if intfTag == tag && !prefix {
			swIfIndex = uint32(response.SwIfIndex)
		}
		if strings.HasPrefix(intfTag, tag) && prefix {
			swIfIndexes[intfTag] = uint32(response.SwIfIndex)
		}
	}
	if prefix {
		return nil, swIfIndex, swIfIndexes
	} else {
		return nil, swIfIndex, nil
	}
}

func (v *Vpp) getInterfaceAddresses(iface *types2.Interface, isv6 bool) (addresses []types2.IfAddress, err error) {
	v.Lock()
	defer v.Unlock()

	request := &vppip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		IsIPv6:    isv6,
	}
	stream := v.GetChannel().SendMultiRequest(request)
	for {
		response := &vppip.IPAddressDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error getting VPP interface addresses")
		}
		if stop {
			break
		}
		address := types2.IfAddress{
			SwIfIndex: uint32(response.SwIfIndex),
			IPNet:     *FromVppAddressWithPrefix(response.Prefix),
		}
		addresses = append(addresses, address)
	}
	return addresses, err
}

func (v *Vpp) SetInterfaceMtu(iface *types2.Interface, mtu int) error {
	v.Lock()
	defer v.Unlock()

	mtus := make([]uint32, 4)
	mtus[interface_types.MTU_PROTO_API_L3] = uint32(mtu)

	response := &interfaces.SwInterfaceSetMtuReply{}
	request := &interfaces.SwInterfaceSetMtu{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		Mtu:       mtus,
	}

	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceSetMtu failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceSetMtu failed (retval %d). Request: %+v", response.Retval, request)
	}
	iface.Mtu = mtu
	return nil
}

func (v *Vpp) SetInterfaceRxMode(iface *types2.Interface, queueID uint32, mode types2.RxMode) error {
	v.Lock()
	defer v.Unlock()

	response := &interfaces.SwInterfaceSetRxModeReply{}
	request := &interfaces.SwInterfaceSetRxMode{
		SwIfIndex:    interface_types.InterfaceIndex(iface.SwIfIndex),
		QueueIDValid: queueID != types2.AllQueues,
		QueueID:      queueID,
		Mode:         interface_types.RxMode(mode),
	}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SetInterfaceRxMode failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SetInterfaceRxMode failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *Vpp) SetInterfaceMacAddress(iface *types2.Interface, mac *net.HardwareAddr) error {
	v.Lock()
	defer v.Unlock()

	response := &interfaces.SwInterfaceSetMacAddressReply{}
	request := &interfaces.SwInterfaceSetMacAddress{
		SwIfIndex:  interface_types.InterfaceIndex(iface.SwIfIndex),
		MacAddress: ToVppMacAddress(mac),
	}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceSetMacAddress failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceSetMacAddress failed (retval %d). Request: %+v", response.Retval, request)
	}
	iface.HardwareAddr = mac
	return nil
}

func (v *Vpp) SetInterfaceVRF(iface *types2.Interface, vrfIndex uint32, isIP6 bool) error {
	v.Lock()
	defer v.Unlock()
	response := &interfaces.SwInterfaceSetTableReply{}
	request := &interfaces.SwInterfaceSetTable{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		IsIPv6:    isIP6,
		VrfID:     vrfIndex,
	}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceSetTable failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceSetTable failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *Vpp) addDelInterfaceAddress(iface *types2.Interface, addr *net.IPNet, isAdd bool) error {
	v.Lock()
	defer v.Unlock()
	if IsIP6(addr.IP) && addr.IP.IsLinkLocalUnicast() {
		_, bits := addr.Mask.Size()
		if bits != 128 {
			return nil
		}
	}
	request := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		IsAdd:     isAdd,
		Prefix:    ToVppAddressWithPrefix(addr),
	}
	response := &interfaces.SwInterfaceAddDelAddressReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Adding IP address failed: req %+v reply %+v", request, response)
	}
	return nil
}

func (v *Vpp) setUnsetInterfaceTag(iface *types2.Interface, tag string, isAdd bool) error {
	v.Lock()
	defer v.Unlock()

	request := &interfaces.SwInterfaceTagAddDel{
		IsAdd:     isAdd,
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		Tag:       tag,
	}
	response := &interfaces.SwInterfaceTagAddDelReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot add interface tag: %v %d", err, response.Retval)
	}
	if isAdd {
		iface.Tag = tag
	} else {
		iface.Tag = ""
	}
	return nil
}

func (v *Vpp) enableDisableGso(iface *types2.Interface, enable bool) error {
	v.Lock()
	defer v.Unlock()

	request := &gso.FeatureGsoEnableDisable{
		SwIfIndex:     interface_types.InterfaceIndex(iface.SwIfIndex),
		EnableDisable: enable,
	}
	response := &gso.FeatureGsoEnableDisableReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot configure gso: %v %d", err, response.Retval)
	}
	iface.Gso = enable
	return nil
}

func (v *Vpp) setInterfacePromiscuous(iface *types2.Interface, promiscOn bool) error {
	v.Lock()
	defer v.Unlock()

	request := &interfaces.SwInterfaceSetPromisc{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		PromiscOn: promiscOn,
	}
	response := &interfaces.SwInterfaceSetPromiscReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot configure gso: %v %d", err, response.Retval)
	}
	iface.PromiscOn = promiscOn
	return nil
}

func (v *Vpp) SetInterfaceTxPlacement(iface *types2.Interface, queue int, worker int) error {
	v.Lock()
	defer v.Unlock()

	request := &interfaces.SwInterfaceSetTxPlacement{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		QueueID:   uint32(queue),
		ArraySize: uint32(1),
		Threads:   []uint32{uint32(worker)},
	}
	response := &interfaces.SwInterfaceSetTxPlacementReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set interface tx placement: %v %d", err, response.Retval)
	}
	return nil
}

func (v *Vpp) SetInterfaceRxPlacement(iface *types2.Interface, queue int, worker int, main bool) error {
	v.Lock()
	defer v.Unlock()

	request := &interfaces.SwInterfaceSetRxPlacement{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		QueueID:   uint32(queue),
		WorkerID:  uint32(worker),
		IsMain:    main,
	}
	response := &interfaces.SwInterfaceSetRxPlacementReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot set interface rx placement: %v %d", err, response.Retval)
	}
	return nil
}

func (v *Vpp) interfaceAdminUpDown(iface *types2.Interface, up bool) error {
	v.Lock()
	defer v.Unlock()

	var f interface_types.IfStatusFlags = 0
	if up {
		f |= interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	}
	// Set interface down
	request := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		Flags:     f,
	}
	response := &interfaces.SwInterfaceSetFlagsReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "setting interface up/down failed")
	}
	return nil
}

func (v *Vpp) enableDisableInterfaceIP(iface *types2.Interface, isIP6 bool, isEnable bool) error {
	v.Lock()
	defer v.Unlock()
	response := &vppip.SwInterfaceIP6EnableDisableReply{}
	request := &vppip.SwInterfaceIP6EnableDisable{
		Enable:    isEnable,
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
	}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "SwInterfaceIP6EnableDisable failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return fmt.Errorf("SwInterfaceIP6EnableDisable failed (retval %d). Request: %+v", response.Retval, request)
	}
	return nil
}

func (v *Vpp) interfaceSetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32, isAdd bool) error {
	v.Lock()
	defer v.Unlock()

	request := &interfaces.SwInterfaceSetUnnumbered{
		SwIfIndex:           interface_types.InterfaceIndex(swIfIndex),
		UnnumberedSwIfIndex: interface_types.InterfaceIndex(unnumberedSwIfIndex),
		IsAdd:               isAdd,
	}
	response := &interfaces.SwInterfaceSetUnnumberedReply{}
	err := v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "setting interface unnumbered failed %d -> %d", unnumberedSwIfIndex, swIfIndex)
	}
	return nil
}

func (v *Vpp) GetInterfaceDetails(iface *types2.Interface) (i *types2.InterfaceDetails, err error) {
	v.Lock()
	defer v.Unlock()

	request := &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
	}
	stream := v.GetChannel().SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.GetLog().Errorf("error listing VPP interfaces: %v", err)
			return nil, err
		}
		if stop {
			break
		}
		if uint32(response.SwIfIndex) != iface.SwIfIndex {
			v.GetLog().Debugf("Got interface that doesn't match filter, fix vpp")
			continue
		}
		v.GetLog().Debugf("found interface %d", response.SwIfIndex)
		i = &types2.InterfaceDetails{
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

func (v *Vpp) GetInterfaceNeighbors(iface *types2.Interface, isIPv6 bool) (err error, neighbors []types2.Neighbor) {
	v.Lock()
	defer v.Unlock()

	request := &ip_neighbor.IPNeighborDump{
		SwIfIndex: interface_types.InterfaceIndex(iface.SwIfIndex),
		Af:        ip_types.ADDRESS_IP4,
	}
	if isIPv6 {
		request.Af = ip_types.ADDRESS_IP6
	}
	response := &ip_neighbor.IPNeighborDetails{}
	stream := v.GetChannel().SendMultiRequest(request)
	for {
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.GetLog().Errorf("error listing VPP neighbors: %v", err)
			return err, nil
		}
		if stop {
			break
		}
		vppNeighbor := response.Neighbor
		neighbors = append(neighbors, types2.Neighbor{
			SwIfIndex:    uint32(vppNeighbor.SwIfIndex),
			Flags:        FromVppNeighborFlags(vppNeighbor.Flags),
			IP:           FromVppAddress(vppNeighbor.IPAddress),
			HardwareAddr: FromVppMacAddress(vppNeighbor.MacAddress),
		})
	}
	return nil, neighbors
}

func (v *Vpp) EnableInterfaceIP46(iface *types2.Interface) (err error) {
	err = v.enableDisableInterfaceIP(iface, false /*isIP6*/, true /*isEnable*/)
	if err != nil {
		return err
	}
	err = v.enableDisableInterfaceIP(iface, true /*isIP6*/, true /*isEnable*/)
	if err != nil {
		return err
	}
	return nil
}

func (v *Vpp) DisableInterfaceIP46(iface *types2.Interface) (err error) {
	err = v.enableDisableInterfaceIP(iface, false /*isIP6*/, false /*isEnable*/)
	if err != nil {
		return err
	}
	err = v.enableDisableInterfaceIP(iface, true /*isIP6*/, false /*isEnable*/)
	if err != nil {
		return err
	}
	return nil
}

func (v *Vpp) DisableInterfaceIP4(iface *types2.Interface) error {
	return v.enableDisableInterfaceIP(iface, false /*isIP6*/, false /*isEnable*/)
}

func (v *Vpp) EnableInterfaceIP4(iface *types2.Interface) error {
	return v.enableDisableInterfaceIP(iface, false /*isIP6*/, true /*isEnable*/)
}

func (v *Vpp) DisableInterfaceIP6(iface *types2.Interface) error {
	return v.enableDisableInterfaceIP(iface, true /*isIP6*/, false /*isEnable*/)
}

func (v *Vpp) EnableInterfaceIP6(iface *types2.Interface) error {
	return v.enableDisableInterfaceIP(iface, true /*isIP6*/, true /*isEnable*/)
}

func (v *Vpp) GetInterfaceAddressesIP4(iface *types2.Interface) ([]types2.IfAddress, error) {
	return v.getInterfaceAddresses(iface, false /*isIP6*/)
}

func (v *Vpp) GetInterfaceAddressesIP6(iface *types2.Interface) ([]types2.IfAddress, error) {
	return v.getInterfaceAddresses(iface, true /*isIP6*/)
}
func (v *Vpp) SetInterfaceVrfIP4(iface *types2.Interface, vrfIndex uint32) error {
	return v.SetInterfaceVRF(iface, vrfIndex, false /*isIP6*/)
}

func (v *Vpp) SetInterfaceVrfIP6(iface *types2.Interface, vrfIndex uint32) error {
	return v.SetInterfaceVRF(iface, vrfIndex, true /*isIP6*/)
}

func (v *Vpp) AddInterfaceAddress(iface *types2.Interface, addr *net.IPNet) error {
	return v.addDelInterfaceAddress(iface, addr, true)
}

func (v *Vpp) DelInterfaceAddress(iface *types2.Interface, addr *net.IPNet) error {
	return v.addDelInterfaceAddress(iface, addr, false)
}

func (v *Vpp) SetInterfaceTag(iface *types2.Interface, tag string) error {
	return v.setUnsetInterfaceTag(iface, tag, true /* isAdd */)
}

func (v *Vpp) UnsetInterfaceTag(iface *types2.Interface, tag string) error {
	return v.setUnsetInterfaceTag(iface, tag, false /* isAdd */)
}

func (v *Vpp) EnableGSOFeature(iface *types2.Interface) error {
	return v.enableDisableGso(iface, true)
}

func (v *Vpp) DisableGSOFeature(iface *types2.Interface) error {
	return v.enableDisableGso(iface, false)
}

func (v *Vpp) SetPromiscOn(iface *types2.Interface) error {
	return v.setInterfacePromiscuous(iface, true)
}

func (v *Vpp) SetPromiscOff(iface *types2.Interface) error {
	return v.setInterfacePromiscuous(iface, false)
}

func (v *Vpp) InterfaceAdminDown(iface *types2.Interface) error {
	return v.interfaceAdminUpDown(iface, false)
}

func (v *Vpp) InterfaceAdminUp(iface *types2.Interface) error {
	return v.interfaceAdminUpDown(iface, true)
}

func (v *Vpp) InterfaceSetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32) error {
	return v.interfaceSetUnnumbered(unnumberedSwIfIndex, swIfIndex, true)
}

func (v *Vpp) InterfaceUnsetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32) error {
	return v.interfaceSetUnnumbered(unnumberedSwIfIndex, swIfIndex, false)
}

func (v *Vpp) SearchInterfaceWithTag(tag string) (uint32, error) {
	err, sw, _ := v.searchInterfaceWithTagOrTagPrefix(tag, false)
	return sw, err
}

func (v *Vpp) SearchInterfacesWithTagPrefix(tag string) (map[string]uint32, error) {
	err, _, sws := v.searchInterfaceWithTagOrTagPrefix(tag, true)
	return sws, err
}
