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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	. "github.com/onsi/gomega"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// VppAssertions provides assertion helpers for VPP state
type VppAssertions struct {
	vpp *vpplink.VppLink
}

// NewVppAssertions creates a new VppAssertions helper
func NewVppAssertions(vpp *vpplink.VppLink) *VppAssertions {
	return &VppAssertions{vpp: vpp}
}

// AssertInterfaceIsUp checks that an interface is administratively up
func (a *VppAssertions) AssertInterfaceIsUp(swIfIndex uint32) {
	details, err := a.vpp.GetInterfaceDetails(swIfIndex)
	Expect(err).ToNot(HaveOccurred(), "failed to dump interfaces")
	Expect(details.IsUp).To(BeTrue(), "interface is not admin up")
}

// AssertMemifInterfaceExists checks that a memif interface exists
func (a *VppAssertions) AssertMemifInterfaceExists(swIfIndex uint32) {
	memifs, err := a.vpp.ListMemifInterfaces()
	Expect(err).ToNot(HaveOccurred(), "failed to dump memif interfaces")

	found := false
	for _, memif := range memifs {
		if memif.SwIfIndex == swIfIndex {
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(), "memif interface %d not found", swIfIndex)
}
