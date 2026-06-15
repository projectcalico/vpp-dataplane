// Copyright (C) 2026 Cisco Systems Inc.
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
	"net"
	"testing"

	bgpapi "github.com/osrg/gobgp/v3/api"
)

// TestMakePathSRv6TunnelColorNonZero verifies that MakePathSRv6Tunnel sets
// a non-zero Color in SRPolicyNLRI, as required by RFC 9256 §2.1:
// "The color is an unsigned non-zero 32-bit integer value."
func TestMakePathSRv6TunnelColorNonZero(t *testing.T) {
	localSid := net.ParseIP("fd00::1")
	bSid := net.ParseIP("fd00::2")
	nodeIPv6 := net.ParseIP("2001:db8::1")

	tests := []struct {
		name         string
		trafficType  int
		wantColor    uint32
		wantBehavior bgpapi.SRv6Behavior
	}{
		{
			name:         "DT4 traffic type sets Color=4",
			trafficType:  4,
			wantColor:    4,
			wantBehavior: bgpapi.SRv6Behavior_END_DT4,
		},
		{
			name:         "DT6 traffic type sets Color=6",
			trafficType:  6,
			wantColor:    6,
			wantBehavior: bgpapi.SRv6Behavior_END_DT6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, err := MakePathSRv6Tunnel(localSid, bSid, nodeIPv6, tc.trafficType, false)
			if err != nil {
				t.Fatalf("MakePathSRv6Tunnel() error: %v", err)
			}

			nlri := &bgpapi.SRPolicyNLRI{}
			if err := path.Nlri.UnmarshalTo(nlri); err != nil {
				t.Fatalf("UnmarshalTo(SRPolicyNLRI) error: %v", err)
			}

			if nlri.Color == 0 {
				t.Fatal("SRPolicyNLRI.Color=0 violates RFC 9256 §2.1 (must be non-zero)")
			}
			if nlri.Color != tc.wantColor {
				t.Errorf("SRPolicyNLRI.Color=%d want=%d", nlri.Color, tc.wantColor)
			}
		})
	}
}

// TestMakePathSRv6TunnelDT4DT6UniqueNLRI verifies that DT4 and DT6 paths for
// the same endpoint produce distinct NLRI keys. Without distinct Color values,
// GoBGP's AddPath treats them as the same policy and the second overwrites the first.
func TestMakePathSRv6TunnelDT4DT6UniqueNLRI(t *testing.T) {
	localSid := net.ParseIP("fd00::1")
	bSid4 := net.ParseIP("fd00::10")
	bSid6 := net.ParseIP("fd00::11")
	nodeIPv6 := net.ParseIP("2001:db8::1")

	pathDT4, err := MakePathSRv6Tunnel(localSid, bSid4, nodeIPv6, 4, false)
	if err != nil {
		t.Fatalf("MakePathSRv6Tunnel(DT4) error: %v", err)
	}
	pathDT6, err := MakePathSRv6Tunnel(localSid, bSid6, nodeIPv6, 6, false)
	if err != nil {
		t.Fatalf("MakePathSRv6Tunnel(DT6) error: %v", err)
	}

	nlri4 := &bgpapi.SRPolicyNLRI{}
	nlri6 := &bgpapi.SRPolicyNLRI{}
	if err := pathDT4.Nlri.UnmarshalTo(nlri4); err != nil {
		t.Fatalf("UnmarshalTo(DT4 NLRI) error: %v", err)
	}
	if err := pathDT6.Nlri.UnmarshalTo(nlri6); err != nil {
		t.Fatalf("UnmarshalTo(DT6 NLRI) error: %v", err)
	}

	if nlri4.Color == nlri6.Color {
		t.Fatalf("DT4 and DT6 have same Color=%d — NLRI collision causes one policy to overwrite the other in GoBGP RIB", nlri4.Color)
	}

	// Endpoint should be the same (same node)
	if !net.IP(nlri4.Endpoint).Equal(net.IP(nlri6.Endpoint)) {
		t.Errorf("Endpoint mismatch: DT4=%s DT6=%s", net.IP(nlri4.Endpoint), net.IP(nlri6.Endpoint))
	}
}
