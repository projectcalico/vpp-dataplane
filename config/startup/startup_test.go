// Copyright (C) 2022 Cisco Systems Inc.
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

package startup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCleanupCoreFiles(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Common CalicoVPP tests")
}

// TestCleanupCoreFiles creates 4 files names file1..file3
// it then calls CleanupCoreFiles() with maxCoreFiles=2 (default)
// we assert that only file2 & file3 remain
// then call CleanupCoreFiles() with maxCoreFiles=0
// and assert no file remain
var _ = Describe("Test CleanupCoreFiles", func() {
	It("Call CleanupCoreFiles with empty string", func() {
		err := CleanupCoreFiles("")
		Expect(err).ToNot(HaveOccurred(), "Error calling CleanupCoreFiles")
	})

	It("Call CleanupCoreFiles with empty string", func() {
		dir, err := os.MkdirTemp("", "TestCleanupCoreFiles")
		Expect(err).ToNot(HaveOccurred(), "Error MkdirTemp")
		for i := 0; i < 4; i++ {
			err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("vppcore.%d", i)), []byte("data"), 0666)
			Expect(err).ToNot(HaveOccurred(), "Error Writing file")
			time.Sleep(100 * time.Millisecond)
		}
		err = os.WriteFile(filepath.Join(dir, "notvppcore"), []byte("data"), 0666)
		Expect(err).ToNot(HaveOccurred(), "Error Writing file")

		err = CleanupCoreFiles(filepath.Join(dir, "vppcore.%e.%p"))
		Expect(err).ToNot(HaveOccurred(), "Error calling CleanupCoreFiles")

		for i := 0; i < 2; i++ {
			_, err = os.Stat(filepath.Join(dir, fmt.Sprintf("vppcore.%d", i)))
			Expect(os.IsNotExist(err)).To(BeTrue(), "vppcore.%d err is not ErrNotExist %s", i)
		}
		for i := 2; i < 4; i++ {
			_, err = os.Stat(filepath.Join(dir, fmt.Sprintf("vppcore.%d", i)))
			Expect(err).ToNot(HaveOccurred(), "vppcore.%d not found", i)
		}
		_, err = os.Stat(filepath.Join(dir, "notvppcore"))
		Expect(err).ToNot(HaveOccurred(), "notvppcore not found")

		maxCoreFiles = 0
		err = CleanupCoreFiles(filepath.Join(dir, "vppcore.%e.%p"))
		Expect(err).ToNot(HaveOccurred(), "Error calling CleanupCoreFiles")

		_, err = os.Stat(filepath.Join(dir, "notvppcore"))
		Expect(err).ToNot(HaveOccurred(), "notvppcore not found")

		err = os.Remove(filepath.Join(dir, "notvppcore"))
		Expect(err).ToNot(HaveOccurred(), "Could not remote notvppcore")

		err = os.Remove(dir)
		Expect(err).ToNot(HaveOccurred(), "Could not remove test directory")
	})
})
