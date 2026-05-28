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

package vppmanager

import (
	"os"
	"syscall"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
)

func TestVppManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VPP Manager Test Suite")
}

var _ = Describe("Vpp should tear down gracefully", func() {
	log := logrus.New()
	log.Out = os.Stdout
	log.Level = logrus.TraceLevel

	testVpp := NewTestVpp(log)
	testVpp.RunTestVpp()
	testVpp.StopTestVpp()

	Expect(testVpp.Err).ToNot(HaveOccurred())
})

var _ = Describe("VppManager should gracefully handle VPP sigint", func() {
	log := logrus.New()
	log.Out = os.Stdout
	log.Level = logrus.TraceLevel

	testVpp := NewTestVpp(log)
	testVpp.RunTestVpp()
	err := testVpp.SignalVpp(syscall.SIGINT)
	Expect(err).ToNot(HaveOccurred())

	testVpp.Wait()

	Expect(testVpp.Err).To(HaveOccurred())
})
