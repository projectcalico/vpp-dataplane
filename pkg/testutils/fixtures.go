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
	"fmt"

	"github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// VppFixture is a Ginkgo fixture to setup and teardown VPP instances in tests
type VppFixture struct {
	Instance *VppInstance
	Config   VppConfig
}

// Setup initializes the VPP fixture
func (f *VppFixture) Setup(name, image, binary string, log *logrus.Logger) {
	if f.Config.WorkersCount == 0 && len(f.Config.EnablePlugins) == 0 {
		f.Config = DefaultVppConfig()
	}

	f.Instance = NewVppInstance(name, image, binary, f.Config, log)

	By(fmt.Sprintf("Starting VPP instance: %s", name))
	err := f.Instance.Start()
	Expect(err).ToNot(HaveOccurred(), "failed to start VPP")

	By(fmt.Sprintf("Connecting to VPP instance: %s", name))
	_, err = f.Instance.Connect()
	Expect(err).ToNot(HaveOccurred(), "failed to connect to VPP")
}

// Teardown cleans up the VPP fixture
func (f *VppFixture) Teardown() {
	if f.Instance != nil {
		By(fmt.Sprintf("Stopping VPP instance: %s", f.Instance.Name))
		_ = f.Instance.Stop()
	}
}
