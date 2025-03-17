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
	"io"
	"net"
	"strings"

	"github.com/pkg/errors"
	"go.fd.io/govpp/api"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/gso"
	interfaces "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	vppip "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_neighbor"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/tapv2"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

const (
	INVALID_SW_IF_INDEX = ^uint32(0)
	MAX_MTU             = 9216
	DEFAULT_QUEUE_SIZE  = 1024
)

type NamespaceNotFound error

func (v *VppLink) SetInterfaceMtu(swIfIndex uint32, mtu int) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	mtus := make([]uint32, 4)
	mtus[interface_types.MTU_PROTO_API_L3] = uint32(mtu)

	_, err := client.SwInterfaceSetMtu(v.GetContext(), &interfaces.SwInterfaceSetMtu{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Mtu:       mtus,
	})
	if err != nil {
		return fmt.Errorf("failed to set interface MTU: %w", err)
	}
	return nil
}

func (v *VppLink) SetInterfaceRxMode(swIfIndex uint32, queueID uint32, mode types.RxMode) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetRxMode(v.GetContext(), &interfaces.SwInterfaceSetRxMode{
		SwIfIndex:    interface_types.InterfaceIndex(swIfIndex),
		QueueIDValid: queueID != types.AllQueues,
		QueueID:      queueID,
		Mode:         interface_types.RxMode(mode),
	})
	if err != nil {
		return fmt.Errorf("failed to set interface RX mode: %w", err)
	}
	return nil
}

func (v *VppLink) SetInterfaceMacAddress(swIfIndex uint32, mac net.HardwareAddr) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetMacAddress(v.GetContext(), &interfaces.SwInterfaceSetMacAddress{
		SwIfIndex:  interface_types.InterfaceIndex(swIfIndex),
		MacAddress: types.MacAddress(mac),
	})
	if err != nil {
		return fmt.Errorf("failed to set interface MAC: %w", err)
	}
	return nil
}

func (v *VppLink) SetInterfaceVRF(swIfIndex, vrfIndex uint32, isIP6 bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetTable(v.GetContext(), &interfaces.SwInterfaceSetTable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIPv6:    isIP6,
		VrfID:     vrfIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to set interface VRF: %w", err)
	}
	return nil
}

func (v *VppLink) CreateTapV2(tap *types.TapV2) (uint32, error) {
	client := tapv2.NewServiceClient(v.GetConnection())

	if len(tap.HostNamespace) > 64 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("HostNamespace must be less than 64 characters")
	}
	if len(tap.HostInterfaceName) > 64 {
		return INVALID_SW_IF_INDEX, fmt.Errorf("HostInterfaceName must be less than 64 characters")
	}

	request := &tapv2.TapCreateV3{
		ID:          ^uint32(0),
		Tag:         tap.Tag,
		TapFlags:    tapv2.TapFlags(tap.Flags),
		NumRxQueues: uint16(DefaultIntTo(tap.NumRxQueues, 1)),
		NumTxQueues: uint16(DefaultIntTo(tap.NumTxQueues, 1)),
		TxRingSz:    uint16(DefaultIntTo(tap.TxQueueSize, DEFAULT_QUEUE_SIZE)),
		RxRingSz:    uint16(DefaultIntTo(tap.RxQueueSize, DEFAULT_QUEUE_SIZE)),
		HostMtuSize: uint32(tap.HostMtu),
		HostMtuSet:  tap.HostMtu != 0,
	}
	if tap.HardwareAddr != nil {
		request.MacAddress = types.MacAddress(tap.HardwareAddr)
	} else {
		request.UseRandomMac = true
	}
	if tap.TxQueueSize > 0 {
		request.TxRingSz = uint16(tap.TxQueueSize)
	}
	if tap.RxQueueSize > 0 {
		request.RxRingSz = uint16(tap.RxQueueSize)
	}
	if tap.HostNamespace != "" {
		request.HostNamespaceSet = true
		request.HostNamespace = tap.HostNamespace
	}
	if tap.HostInterfaceName != "" {
		request.HostIfNameSet = true
		request.HostIfName = tap.HostInterfaceName
	}
	if tap.HostMacAddress != nil {
		request.HostMacAddrSet = true
		request.HostMacAddr = types.MacAddress(tap.HostMacAddress)
	}
	response, err := client.TapCreateV3(v.GetContext(), request)
	if err != nil {
		if err == api.SYSCALL_ERROR_2 {
			return INVALID_SW_IF_INDEX, nil
		}
		return 0, fmt.Errorf("failed to create tap: %w", err)
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
	client := interfaces.NewServiceClient(v.GetConnection())

	if IsIP6(addr.IP) && addr.IP.IsLinkLocalUnicast() {
		_, bits := addr.Mask.Size()
		if bits != 128 {
			return nil
		}
	}

	_, err := client.SwInterfaceAddDelAddress(v.GetContext(), &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     isAdd,
		Prefix:    types.ToVppAddressWithPrefix(addr),
	})
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) DelInterfaceAddress(swIfIndex uint32, addr *net.IPNet) error {
	if err := v.addDelInterfaceAddress(swIfIndex, addr, false); err != nil {
		return fmt.Errorf("failed to delete interface address: %w", err)
	}
	return nil
}

func (v *VppLink) AddInterfaceAddress(swIfIndex uint32, addr *net.IPNet) error {
	if err := v.addDelInterfaceAddress(swIfIndex, addr, true); err != nil {
		return fmt.Errorf("failed to add interface address: %w", err)
	}
	return nil
}

func (v *VppLink) setUnsetInterfaceTag(swIfIndex uint32, tag string, isAdd bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceTagAddDel(v.GetContext(), &interfaces.SwInterfaceTagAddDel{
		IsAdd:     isAdd,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Tag:       tag,
	})
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) SetInterfaceTag(swIfIndex uint32, tag string) error {
	if err := v.setUnsetInterfaceTag(swIfIndex, tag, true); err != nil {
		return fmt.Errorf("failed to set interface tag: %w", err)
	}
	return nil
}

func (v *VppLink) UnsetInterfaceTag(swIfIndex uint32, tag string) error {
	if err := v.setUnsetInterfaceTag(swIfIndex, tag, false); err != nil {
		return fmt.Errorf("failed to unset interface tag: %w", err)
	}
	return nil
}

func (v *VppLink) enableDisableInterfaceIP(swIfIndex uint32, isIP6 bool, isEnable bool) error {
	client := vppip.NewServiceClient(v.GetConnection())

	// TODO: IP4 is not implemented

	_, err := client.SwInterfaceIP6EnableDisable(v.GetContext(), &vppip.SwInterfaceIP6EnableDisable{
		Enable:    isEnable,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to %v interface %v: %w", strEnableDisable[isEnable], strIP46[isIP6], err)
	}
	return nil
}

func (v *VppLink) EnableInterfaceIP46(swIfIndex uint32) (err error) {
	err = v.enableDisableInterfaceIP(swIfIndex, false, true)
	if err != nil {
		return err
	}
	err = v.enableDisableInterfaceIP(swIfIndex, true, true)
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) DisableInterfaceIP46(swIfIndex uint32) (err error) {
	err = v.enableDisableInterfaceIP(swIfIndex, false, false)
	if err != nil {
		return err
	}
	err = v.enableDisableInterfaceIP(swIfIndex, true, false)
	if err != nil {
		return err
	}
	return nil
}

func (v *VppLink) DisableInterfaceIP6(swIfIndex uint32) error {
	return v.enableDisableInterfaceIP(swIfIndex, true, false)
}

func (v *VppLink) EnableInterfaceIP6(swIfIndex uint32) error {
	return v.enableDisableInterfaceIP(swIfIndex, true, true)
}

func (v *VppLink) DisableInterfaceIP4(swIfIndex uint32) error {
	return v.enableDisableInterfaceIP(swIfIndex, false, false)
}

func (v *VppLink) EnableInterfaceIP4(swIfIndex uint32) error {
	return v.enableDisableInterfaceIP(swIfIndex, false, true)
}

// SearchInterfaceWithTag searches for interface that is tagged with given prefix. If not such interface is found,
// then vpplink.INVALID_SW_IF_INDEX is returned as interface swIndex. Otherwise, non-nil error is returned.
func (v *VppLink) SearchInterfaceWithTag(tag string) (uint32, error) {
	err, sw, _ := v.searchInterfaceWithTagOrTagPrefix(tag, false)
	return sw, err
}

func (v *VppLink) SearchInterfacesWithTagPrefix(tag string) (map[string]uint32, error) {
	err, _, sws := v.searchInterfaceWithTagOrTagPrefix(tag, true)
	return sws, err
}

func (v *VppLink) searchInterfaceWithTagOrTagPrefix(tag string, prefix bool) (err error, swIfIndex uint32, swIfIndexes map[string]uint32) {
	client := interfaces.NewServiceClient(v.GetConnection())

	swIfIndex = INVALID_SW_IF_INDEX
	swIfIndexes = make(map[string]uint32)

	stream, err := client.SwInterfaceDump(v.GetContext(), &interfaces.SwInterfaceDump{})
	if err != nil {
		return fmt.Errorf("failed to dump interfaces: %w", err), INVALID_SW_IF_INDEX, swIfIndexes
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to dump interfaces: %w", err), INVALID_SW_IF_INDEX, swIfIndexes
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
	}
	return nil, swIfIndex, nil
}

func (v *VppLink) SearchInterfaceWithName(name string) (swIfIndex uint32, err error) {
	client := interfaces.NewServiceClient(v.GetConnection())

	swIfIndex = INVALID_SW_IF_INDEX

	stream, err := client.SwInterfaceDump(v.GetContext(), &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(INVALID_SW_IF_INDEX),
		// TODO: filter by name with NameFilter
	})
	if err != nil {
		return INVALID_SW_IF_INDEX, fmt.Errorf("failed to dump interfaces: %w", err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return INVALID_SW_IF_INDEX, fmt.Errorf("failed to dump interfaces: %w", err)
		}
		interfaceName := response.InterfaceName
		if interfaceName == name {
			swIfIndex = uint32(response.SwIfIndex)
			v.GetLog().Debugf("found interface with name %q (%v)", interfaceName, swIfIndex)
		}
	}
	if swIfIndex == INVALID_SW_IF_INDEX {
		v.GetLog().Errorf("Interface %s not found", name)
		return INVALID_SW_IF_INDEX, errors.New("Interface not found")
	}
	return swIfIndex, nil
}

func (v *VppLink) GetInterfaceDetails(swIfIndex uint32) (i *types.VppInterfaceDetails, err error) {
	client := interfaces.NewServiceClient(v.GetConnection())

	stream, err := client.SwInterfaceDump(v.GetContext(), &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump interfaces: %w", err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump interfaces: %w", err)
		}
		if uint32(response.SwIfIndex) != swIfIndex {
			v.GetLog().Debugf("Got interface that doesn't match filter, fix vpp")
			continue
		}
		v.GetLog().Debugf("found interface %d", response.SwIfIndex)
		i = &types.VppInterfaceDetails{
			SwIfIndex: uint32(response.SwIfIndex),
			IsUp:      response.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP > 0,
			Name:      response.InterfaceName,
			Tag:       response.Tag,
			Type:      response.InterfaceDevType,
			Mtu:       response.Mtu,
		}
	}
	if i == nil {
		return nil, errors.New("Interface not found")
	}
	return i, nil
}

func (v *VppLink) interfaceAdminUpDown(swIfIndex uint32, up bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	var f interface_types.IfStatusFlags
	if up {
		f |= interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	}
	_, err := client.SwInterfaceSetFlags(v.GetContext(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Flags:     f,
	})
	if err != nil {
		return fmt.Errorf("failed to set interface %s failed: %w", strUpDown[up], err)
	}
	return nil
}

func (v *VppLink) InterfaceAdminDown(swIfIndex uint32) error {
	return v.interfaceAdminUpDown(swIfIndex, false)
}

func (v *VppLink) InterfaceAdminUp(swIfIndex uint32) error {
	return v.interfaceAdminUpDown(swIfIndex, true)
}

func (v *VppLink) GetInterfaceNeighbors(swIfIndex uint32, isIPv6 bool) (neighbors []types.Neighbor, err error) {
	client := ip_neighbor.NewServiceClient(v.GetConnection())

	request := &ip_neighbor.IPNeighborDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Af:        ip_types.ADDRESS_IP4,
	}
	if isIPv6 {
		request.Af = ip_types.ADDRESS_IP6
	}

	stream, err := client.IPNeighborDump(v.GetContext(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to dump IP neighbors: %w", err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump IP neighbors: %w", err)
		}
		neighbors = append(neighbors, types.Neighbor{
			SwIfIndex:    uint32(response.Neighbor.SwIfIndex),
			Flags:        types.FromVppNeighborFlags(response.Neighbor.Flags),
			IP:           response.Neighbor.IPAddress.ToIP(),
			HardwareAddr: response.Neighbor.MacAddress.ToMAC(),
		})
	}

	return neighbors, nil
}

func (v *VppLink) DelTap(swIfIndex uint32) error {
	client := tapv2.NewServiceClient(v.GetConnection())

	_, err := client.TapDeleteV2(v.GetContext(), &tapv2.TapDeleteV2{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to delete tap from VPP: %w", err)
	}
	return nil
}

func (v *VppLink) InterfaceGetUnnumbered(swIfIndex uint32) (result []*vppip.IPUnnumberedDetails, err error) {
	client := vppip.NewServiceClient(v.GetConnection())

	stream, err := client.IPUnnumberedDump(v.GetContext(), &vppip.IPUnnumberedDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump unnumbered interface %d: %w", swIfIndex, err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump unnumbered interface %d: %w", swIfIndex, err)
		}
		result = append(result, response)
	}
	return
}

func (v *VppLink) interfaceSetUnnumbered(unnumberedSwIfIndex uint32, swIfIndex uint32, isAdd bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetUnnumbered(v.GetContext(), &interfaces.SwInterfaceSetUnnumbered{
		SwIfIndex:           interface_types.InterfaceIndex(swIfIndex),
		UnnumberedSwIfIndex: interface_types.InterfaceIndex(unnumberedSwIfIndex),
		IsAdd:               isAdd,
	})
	if err != nil {
		return fmt.Errorf("failed to %s interface unnumbered (%d -> %d): %w", strSetUnset[isAdd], unnumberedSwIfIndex, swIfIndex, err)
	}
	return nil
}

func (v *VppLink) AddrList(swIfIndex uint32, isv6 bool) (addresses []types.IfAddress, err error) {
	client := vppip.NewServiceClient(v.GetConnection())

	stream, err := client.IPAddressDump(v.GetContext(), &vppip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIPv6:    isv6,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump interface (%d) %v addresses: %w", swIfIndex, strIP46[isv6], err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump interface (%d) %v addresses: %w", swIfIndex, strIP46[isv6], err)
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

func (v *VppLink) enableDisableGso(swIfIndex uint32, enable bool) error {
	client := gso.NewServiceClient(v.GetConnection())

	_, err := client.FeatureGsoEnableDisable(v.GetContext(), &gso.FeatureGsoEnableDisable{
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		EnableDisable: enable,
	})
	if err != nil {
		return fmt.Errorf("failed to %s gso: %w", strEnableDisable[enable], err)
	}
	return nil
}

func (v *VppLink) setInterfacePromiscuous(swIfIndex uint32, promiscOn bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetPromisc(v.GetContext(), &interfaces.SwInterfaceSetPromisc{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		PromiscOn: promiscOn,
	})
	if err != nil {
		return fmt.Errorf("failed to %s promisc: %w", strEnableDisable[promiscOn], err)
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

func (v *VppLink) SetInterfaceTxPlacement(swIfIndex uint32, queue int, worker int) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetTxPlacement(v.GetContext(), &interfaces.SwInterfaceSetTxPlacement{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		QueueID:   uint32(queue),
		ArraySize: uint8(1),
		Threads:   []uint32{uint32(worker)},
	})
	if err != nil {
		return fmt.Errorf("failed to set interface TX placement: %w", err)
	}
	return nil
}

func (v *VppLink) SetInterfaceRxPlacement(swIfIndex uint32, queue int, worker int, main bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.SwInterfaceSetRxPlacement(v.GetContext(), &interfaces.SwInterfaceSetRxPlacement{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		QueueID:   uint32(queue),
		WorkerID:  uint32(worker),
		IsMain:    main,
	})
	if err != nil {
		return fmt.Errorf("failed to set interface RX placement: %w", err)
	}
	return nil
}

func (v *VppLink) CreateLoopback(hwAddr net.HardwareAddr) (swIfIndex uint32, err error) {
	client := interfaces.NewServiceClient(v.GetConnection())

	response, err := client.CreateLoopback(v.GetContext(), &interfaces.CreateLoopback{
		MacAddress: types.MacAddress(hwAddr),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to create loopback interface: %w", err)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *VppLink) DeleteLoopback(swIfIndex uint32) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.DeleteLoopback(v.GetContext(), &interfaces.DeleteLoopback{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to delete loopback interface: %w", err)
	}
	return nil
}

func (v *VppLink) wantInterfaceEvents(on bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	request := &interfaces.WantInterfaceEvents{
		PID: v.pid,
	}
	if on {
		request.EnableDisable = 1
	}
	_, err := client.WantInterfaceEvents(v.GetContext(), request)
	if err != nil {
		return fmt.Errorf("failed to %s interface events: %w", strEnableDisable[on], err)
	}
	return nil
}

// processEvents handles interface event subscription and dispatches incoming events to watchers
func (v *VppLink) processEvents() (func() error, error) {
	// subscribe for specific notification message
	sub, err := v.GetConnection().WatchEvent(v.GetContext(), (*interfaces.SwInterfaceEvent)(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to watch VPP interface events: %w", err)
	}

	// send request to enable interface events
	if err := v.wantInterfaceEvents(true); err != nil {
		return nil, fmt.Errorf("failed to enable interface events: %w", err)
	}

	// process incoming notifications
	go func() {
		v.GetLog().Infof("waiting for incoming VPP interface events")
		defer v.GetLog().Infof("done waiting for incoming VPP notifications")

		for notif := range sub.Events() {
			e, ok := notif.(*interfaces.SwInterfaceEvent)
			if !ok {
				v.GetLog().Warnf("invalid notification type: %#v", e)
				continue
			}
			v.GetLog().Infof("incoming VPP interface event: %+v\n", e)
			event := types.ToInterfaceEvent(e)

			v.watcherLock.Lock()
			// dispatch to the active watchers
			for _, watcher := range v.interfaceEventWatchers {
				if watcher.swIfIndex != event.SwIfIndex {
					continue
				}
				select {
				case watcher.events <- event:
					// event accepted
				default:
					v.GetLog().Warnf("interface event watcher channel busy, dropping event: %+v", event)
				}
			}
			v.watcherLock.Unlock()
		}
	}()

	stop := func() error {
		if err := v.wantInterfaceEvents(false); err != nil {
			return fmt.Errorf("failed to disable interface events: %w", err)
		}

		// unsubscribe from delivery of the notifications
		sub.Close()

		return nil
	}

	return stop, nil
}

type InterfaceEventWatcher interface {
	Stop()
	Events() <-chan types.InterfaceEvent
}

// WatchInterfaceEvents starts a watcher of interface events for specific swIfIndex,
// it returns InterfaceEventWatcher or error if any.
func (v *VppLink) WatchInterfaceEvents(swIfIndex uint32) (InterfaceEventWatcher, error) {
	w := &interfaceEventWatcher{
		swIfIndex: swIfIndex,
		stop:      make(chan struct{}),
		events:    make(chan types.InterfaceEvent, 10),
	}

	v.watcherLock.Lock()
	// begin event processing if this is first watcher
	if len(v.interfaceEventWatchers) == 0 {
		if v.stopEvents != nil {
			v.GetLog().Warnf("events already set before first watcher")
		} else {
			var err error
			v.stopEvents, err = v.processEvents()
			if err != nil {
				v.GetLog().Warnf("error start processing interface events: %v", err)
				v.watcherLock.Unlock()
				return nil, err
			} else {
				v.GetLog().Infof("start processing events before first watcher")
			}
		}
	}
	// add watcher to the list
	v.interfaceEventWatchers = append(v.interfaceEventWatchers, w)
	v.watcherLock.Unlock()

	go func() {
		// wait until watcher stops
		<-w.stop
		v.GetLog().WithField("swIfIdx", swIfIndex).Infof("stopped interface event watcher")

		v.watcherLock.Lock()
		// remove watcher from the list
		for i, item := range v.interfaceEventWatchers {
			if item == w {
				// close event channel
				close(v.interfaceEventWatchers[i].events)
				// remove i-th item in the slice
				v.interfaceEventWatchers = append(v.interfaceEventWatchers[:i], v.interfaceEventWatchers[i+1:]...)
				break
			}
		}
		// stop even processing if this was last watcher
		if len(v.interfaceEventWatchers) == 0 {
			if v.stopEvents == nil {
				v.GetLog().Warnf("events not set after last watcher")
			} else {
				if err := v.stopEvents(); err != nil {
					v.GetLog().Warnf("error stop watching interface events: %v", err)
				} else {
					v.GetLog().Infof("stop processing events after last watcher")
				}
				v.stopEvents = nil
			}
		}
		v.watcherLock.Unlock()
	}()

	return w, nil
}

type interfaceEventWatcher struct {
	swIfIndex uint32
	stop      chan struct{}
	events    chan types.InterfaceEvent
}

func (i *interfaceEventWatcher) Stop() {
	if i.stop == nil {
		return
	}
	close(i.stop)
	i.stop = nil
}

func (i *interfaceEventWatcher) Events() <-chan types.InterfaceEvent {
	return i.events
}
