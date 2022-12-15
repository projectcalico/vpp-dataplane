// Copyright (C) 2021 Cisco Systems Inc.
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

package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCleanupCoreFiles(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "vpp-manager utils tests")
}

var _ = Describe("Test CleanupCoreFiles", func() {
	It("TestIncrementDecrement", func() {
		var incDecPairs = []struct{ low, high net.IP }{
			{net.ParseIP("192.168.2.0"), net.ParseIP("192.168.2.1")},
			{net.ParseIP("192.168.2.4"), net.ParseIP("192.168.2.5")},
			{net.ParseIP("192.168.2.255"), net.ParseIP("192.168.3.0")},
			{net.ParseIP("192.167.255.255"), net.ParseIP("192.168.0.0")},
			{net.ParseIP("9.255.255.255"), net.ParseIP("10.0.0.0")},
			{net.ParseIP("255.255.255.255"), net.ParseIP("0.0.0.0")},
			{net.ParseIP("fd00::1000"), net.ParseIP("fd00::1001")},
			{net.ParseIP("fd00::0fff"), net.ParseIP("fd00::1000")},
			{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), net.ParseIP("::")},
			{net.ParseIP("0:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), net.ParseIP("1::")},
		}
		for _, tc := range incDecPairs {
			Expect(DecrementIP(tc.high).Equal(tc.low)).To(BeTrue())
			Expect(IncrementIP(tc.low).Equal(tc.high)).To(BeTrue())
		}
	})

	It("TestNetworkBroadcastAddr", func() {
		network := func(address string) *net.IPNet {
			_, n, err := net.ParseCIDR(address)
			Expect(err).ToNot(HaveOccurred(), "Error parsing %s", address)
			return n
		}

		var networks = []struct {
			netAddr, brdAddr net.IP
			network          string
		}{
			{net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), "10.0.0.1/24"},
			{net.ParseIP("0.0.0.0"), net.ParseIP("255.255.255.255"), "0.0.0.0/0"},
			{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255"), "192.168.123.123/16"},
			{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.0.63"), "192.168.0.0/26"},
			{net.ParseIP("::"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "::/0"},
			{net.ParseIP("fd01::"), net.ParseIP("fd01::ffff:ffff:ffff:ffff"), "fd01::1/64"},
			{net.ParseIP("fd01::"), net.ParseIP("fd01::3"), "fd01::1/126"},
		}
		for _, d := range networks {
			Expect(NetworkAddr(network(d.network)).Equal(d.netAddr)).To(BeTrue())
			Expect(BroadcastAddr(network(d.network)).Equal(d.brdAddr)).To(BeTrue())
		}
	})
})

// TestCleanupCoreFiles creates 4 files names file1..file3
// it then calls CleanupCoreFiles() with maxCoreFiles=2 (default)
// we assert that only file2 & file3 remain
// then call CleanupCoreFiles() with maxCoreFiles=0
// and assert no file remain
var _ = Describe("Test CleanupCoreFiles", func() {
	It("Call CleanupCoreFiles with empty string", func() {
		err := CleanupCoreFiles("", 2 /* maxCorefiles */)
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

		err = CleanupCoreFiles(filepath.Join(dir, "vppcore.%e.%p"), 2 /* maxCorefiles */)
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

		err = CleanupCoreFiles(filepath.Join(dir, "vppcore.%e.%p"), 0 /* maxCorefiles */)
		Expect(err).ToNot(HaveOccurred(), "Error calling CleanupCoreFiles")

		_, err = os.Stat(filepath.Join(dir, "notvppcore"))
		Expect(err).ToNot(HaveOccurred(), "notvppcore not found")

		err = os.Remove(filepath.Join(dir, "notvppcore"))
		Expect(err).ToNot(HaveOccurred(), "Could not remote notvppcore")

		err = os.Remove(dir)
		Expect(err).ToNot(HaveOccurred(), "Could not remove test directory")
	})
})
