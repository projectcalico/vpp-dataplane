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

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/tracedump"
)

// setTraceFilterFunction sets the filter function for trace
func (v *VppLink) setTraceFilterFunction(name string) error {
	client := tracedump.NewServiceClient(v.GetConnection())
	_, err := client.TraceSetFilterFunction(v.GetContext(), &tracedump.TraceSetFilterFunction{
		FilterFunctionName: name,
	})
	if err != nil {
		return fmt.Errorf("failed to set trace filter function: %w", err)
	}
	return nil
}

// TraceSetDefaultFunction resets trace to use default filtering
func (v *VppLink) TraceSetDefaultFunction() error {
	return v.setTraceFilterFunction("vnet_is_packet_traced")
}

// TraceCapture starts VPP trace capture on an input node
func (v *VppLink) TraceCapture(inputNode uint32, maxPackets uint32, useFilter bool) error {
	client := tracedump.NewServiceClient(v.GetConnection())

	_, err := client.TraceCapturePackets(v.GetContext(), &tracedump.TraceCapturePackets{
		NodeIndex:       inputNode,
		MaxPackets:      maxPackets,
		UseFilter:       useFilter,
		Verbose:         true,
		PreCaptureClear: true,
	})
	if err != nil {
		return fmt.Errorf("failed to capture trace: %w", err)
	}
	return nil
}

// TraceClear clears the trace buffer
func (v *VppLink) TraceClear() error {
	client := tracedump.NewServiceClient(v.GetConnection())

	_, err := client.TraceClearCapture(v.GetContext(), &tracedump.TraceClearCapture{})
	if err != nil {
		return fmt.Errorf("failed to clear capture trace: %w", err)
	}
	return nil
}

// TraceDump dumps the trace buffer and returns the trace output as a string
func (v *VppLink) TraceDump() (string, error) {
	client := tracedump.NewServiceClient(v.GetConnection())

	stream, err := client.TraceDump(v.GetContext(), &tracedump.TraceDump{
		ClearCache: 1,
		ThreadID:   0,
		Position:   0,
		MaxRecords: 50000, // assuming a max count of 50000
	})
	if err != nil {
		return "", fmt.Errorf("failed to start trace dump: %w", err)
	}

	var result string
	for {
		details, reply, err := stream.Recv()
		if err != nil {
			// Check if it's EOF (end of stream)
			if err.Error() == "EOF" {
				break
			}
			return result, fmt.Errorf("failed to receive trace details: %w", err)
		}

		if details != nil {
			result += details.TraceData
			if details.Done != 0 {
				break
			}
		}

		if reply != nil {
			break
		}
	}

	return result, nil
}
