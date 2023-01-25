// Copyright (C) 2023 Cisco Systems Inc.
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

package types

import (
	gerrors "errors"
	"github.com/pkg/errors"
	"go.fd.io/govpp/api"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCommonConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "vpplink types tests")
}

var _ = Describe("Test Vpplink types", func() {
	It("Vpplink errors comparisons testing", func() {
		err := api.RetvalToVPPApiError(int32(api.UNIMPLEMENTED))
		err = errors.Wrapf(err, "Something else")
		Expect(gerrors.Is(err, VppErrorUnimplemented)).To(BeTrue())
		err = api.RetvalToVPPApiError(int32(api.SYSCALL_ERROR_1))
		Expect(gerrors.Is(err, VppErrorUnimplemented)).To(BeFalse())
	})
})
