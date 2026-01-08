// Copyright (C) 2025 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpplink

import (
	"fmt"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/bpf_trace_filter"
	interfaces "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
)

// setPcapFilterFunction sets the filter function for PCAP capture
func (v *VppLink) setPcapFilterFunction(name string) error {
	client := interfaces.NewServiceClient(v.GetConnection())
	_, err := client.PcapSetFilterFunction(v.GetContext(), &interfaces.PcapSetFilterFunction{
		FilterFunctionName: name,
	})
	if err != nil {
		return fmt.Errorf("failed to set pcap filter function: %w", err)
	}
	return nil
}

// PcapSetDefaultFunction resets PCAP to use default filtering
func (v *VppLink) PcapSetDefaultFunction() error {
	return v.setPcapFilterFunction("vnet_is_packet_traced")
}

// SetBpfFunction enables BPF filtering for either PCAP or trace
func (v *VppLink) SetBpfFunction(isPcap bool) error {
	if isPcap {
		return v.setPcapFilterFunction("bpf_trace_filter")
	}
	return v.setTraceFilterFunction("bpf_trace_filter")
}

// UnsetBpfFunction disables BPF filtering and reverts to default
func (v *VppLink) UnsetBpfFunction(isPcap bool) error {
	if isPcap {
		return v.PcapSetDefaultFunction()
	}
	return v.TraceSetDefaultFunction()
}

// PcapTraceOn starts PCAP packet capture
func (v *VppLink) PcapTraceOn(filename string, maxPackets, maxBytesPerPacket, swIfIndex uint32,
	captureRx, captureTx, captureDrop, useFilter, preallocateData, freeData bool,
) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.PcapTraceOn(v.GetContext(), &interfaces.PcapTraceOn{
		CaptureRx:         captureRx,
		CaptureTx:         captureTx,
		CaptureDrop:       captureDrop,
		Filter:            useFilter,
		PreallocateData:   preallocateData,
		FreeData:          freeData,
		MaxPackets:        maxPackets,
		MaxBytesPerPacket: maxBytesPerPacket,
		SwIfIndex:         interface_types.InterfaceIndex(swIfIndex),
		Filename:          filename,
	})
	if err != nil {
		return fmt.Errorf("failed to start pcap trace on interface: %w", err)
	}
	return nil
}

// PcapTraceOff stops PCAP packet capture
func (v *VppLink) PcapTraceOff() error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.PcapTraceOff(v.GetContext(), &interfaces.PcapTraceOff{})
	if err != nil {
		return fmt.Errorf("failed to stop pcap trace on interface: %w", err)
	}
	return nil
}

// PcapDispatchTraceOn starts dispatch trace capture
func (v *VppLink) PcapDispatchTraceOn(maxPackets uint32, filename string, useFilter bool) error {
	client := interfaces.NewServiceClient(v.GetConnection())

	_, err := client.PcapTraceOn(v.GetContext(), &interfaces.PcapTraceOn{
		CaptureRx:         true,
		CaptureTx:         true,
		CaptureDrop:       false,
		Filter:            useFilter,
		PreallocateData:   false,
		FreeData:          false,
		MaxPackets:        maxPackets,
		MaxBytesPerPacket: 0,
		SwIfIndex:         interface_types.InterfaceIndex(^uint32(0)), // all interfaces
		Filename:          filename,
	})
	if err != nil {
		return fmt.Errorf("failed to start dispatch trace: %w", err)
	}
	return nil
}

// PcapDispatchTraceOff stops dispatch trace capture
func (v *VppLink) PcapDispatchTraceOff() error {
	return v.PcapTraceOff()
}

// bpfAddDelExpression adds or deletes a BPF filter expression
func (v *VppLink) bpfAddDelExpression(filter string, isAdd bool) error {
	client := bpf_trace_filter.NewServiceClient(v.GetConnection())

	_, err := client.BpfTraceFilterSetV2(v.GetContext(), &bpf_trace_filter.BpfTraceFilterSetV2{
		IsAdd:    isAdd,
		Filter:   filter,
		Optimize: true,
	})
	if err != nil {
		return fmt.Errorf("failed to update BPF filter: %w", err)
	}
	return nil
}

// BpfAdd adds a BPF filter expression
func (v *VppLink) BpfAdd(filter string) error {
	return v.bpfAddDelExpression(filter, true)
}

// BpfDel removes all BPF filter expressions
func (v *VppLink) BpfDel() error {
	return v.bpfAddDelExpression("", false)
}
