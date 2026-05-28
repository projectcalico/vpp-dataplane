// Copyright (C) 2020 Cisco Systems Inc.
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
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/uplink"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	. "github.com/onsi/ginkgo/v2"
)

type TestVpp struct {
	log        *logrus.Logger
	namedNetns bool
	wg         sync.WaitGroup
	cancel     context.CancelFunc
	Err        error
	runner     *VppRunner
	vppIsRunningChan chan bool
	ctx context.Context
}

func NewTestVpp(log *logrus.Logger) *TestVpp {
	return &TestVpp{log: log}
}

func (vpp *TestVpp) SignalVpp(sig syscall.Signal) error {
	return vpp.runner.vppProcess.Signal(sig)
}

func (vpp *TestVpp) StopTestVpp() {
	vpp.log.Debug("called StopTestVpp()")
	vpp.cancel()
	vpp.wg.Wait()
	vpp.log.Debug("TestVPP terminated")
}

func (vpp *TestVpp) Wait() {
	vpp.wg.Wait()
	vpp.log.Debug("TestVPP terminated")
}

func (vpp *TestVpp) RunTestVpp() {
	vpp.ctx, vpp.cancel = context.WithCancel(context.Background())
	vpp.vppIsRunningChan = make(chan bool)

	if runtime.NumCPU() <= 1 {
		vpp.log.Panicf("This test needs multiple cores to run, %d available", runtime.NumCPU())
	}

	if runtime.GOMAXPROCS(0) <= 1 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}
	vpp.log.Debugf("Using GOMAXPROCS %d NumCPU %d", runtime.GOMAXPROCS(0), runtime.NumCPU())

	vpp.wg.Go(vpp.testVppRunRoutine)

	<-vpp.vppIsRunningChan
	vpp.log.Debug("Test VPP is running")
}


func (vpp *TestVpp) testVppRunRoutine() {
	var vppNs, phyNs netns.NsHandle

	defer GinkgoRecover()

	// this requires GOMAXPROCS > 1
	vpp.log.Debug("Locking OS thread")
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	vpp.log.Debug("Getting current netns")
	testNs, err := netns.Get()
	if err != nil {
		vpp.log.Panic(err)
	}
	defer func() {
		err := netns.Set(testNs)
		if err != nil {
			vpp.log.Panic(err)
		}

		err = testNs.Close()
		if err != nil {
			vpp.log.Panic(err)
		}
	}()

	vpp.log.Debug("create a netns to run VPP")
	// create a netns to run VPP
	if vpp.namedNetns {
		vppNs, err = netns.NewNamed("test-vpp")
	} else {
		vppNs, err = netns.New()
	}
	if err != nil {
		vpp.log.Panic(err)
	}
	defer func() {
		err := vppNs.Close()
		if err != nil {
			vpp.log.Panic(err)
		}
		if vpp.namedNetns {
			err = netns.DeleteNamed("test-vpp")
			if err != nil {
				vpp.log.Panic(err)
			}
		}
	}()

	// create a physical netns representing the
	// physical network
	vpp.log.Debug("create a netns representing the host")
	if vpp.namedNetns {
		phyNs, err = netns.NewNamed("test-phy")
	} else {
		phyNs, err = netns.New()
	}
	if err != nil {
		vpp.log.Panic(err)
	}
	defer func() {
		err := phyNs.Close()
		if err != nil {
			vpp.log.Panic(err)
		}
		if vpp.namedNetns {
			err = netns.DeleteNamed("test-phy")
			if err != nil {
				vpp.log.Panic(err)
			}
		}
	}()

	vpp.log.Debug("adding veths in both netns")
	err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			NetNsID:   -1,
			TxQLen:    -1,
			Name:      "eth0",
			Namespace: netlink.NsFd(vppNs),
		},
		PeerName:      "eth0",
		PeerNamespace: netlink.NsFd(phyNs),
	})
	if err != nil {
		vpp.log.Panic(err)
	}

	vpp.log.Debug("configuring veths")
	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		vpp.log.Panic(err)
	}
	addr, _ := netlink.ParseAddr("192.168.0.2/24")
	err = netlink.AddrAdd(eth0, addr)
	if err != nil {
		vpp.log.Panic(err)
	}
	err = netlink.LinkSetUp(eth0)
	if err != nil {
		vpp.log.Panic(err)
	}
	netns.Set(vppNs)

	eth0, err = netlink.LinkByName("eth0")
	if err != nil {
		vpp.log.Panic(err)
	}
	addr, _ = netlink.ParseAddr("192.168.0.1/24")
	err = netlink.AddrAdd(eth0, addr)
	if err != nil {
		vpp.log.Panic(err)
	}
	err = netlink.LinkSetUp(eth0)
	if err != nil {
		vpp.log.Panic(err)
	}
	intf := &params.VppManagerInterface{
		Spec: config.UplinkInterfaceSpec{
			IsMain:        true,
			InterfaceName: "eth0",
			VppDriver:     uplink.NativeDriverAfPacket,
		},
		State: &config.LinuxInterfaceState{
			IsUp: true,
			// Addresses: []netlink.Addr,
			// Routes: []netlink.Route
			NumTxQueues:   1,
			NumRxQueues:   1,
			InterfaceName: "eth0",
			IsVeth:        true,
		},
	}
	vpp_startup_conf_file, err := os.CreateTemp("", "vpp-startup-conf")
	if err != nil {
		vpp.log.Panic(err)
	}
	vpp_startup_exec_file, err := os.CreateTemp("", "vpp-startup-exec")
	if err != nil {
		vpp.log.Panic(err)
	}
	params := &params.VppManagerParams{
		MachineState: &config.MachineState{
			VppManagerNs: fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), syscall.Gettid()),
		},
		Interfaces: map[string]*params.VppManagerInterface{
			"eth0": intf,
		},
		DisableUpdateCalicoNode: true, // FIXME
		InterfacesByID:          []*params.VppManagerInterface{intf},
		VppConfigFile:           vpp_startup_conf_file.Name(),
		VppConfigExecFile:       vpp_startup_exec_file.Name(),
		VppPath:                 "../../vpp_build/build-root/build-vpp_debug-native/vpp/bin/vpp",
	}
	intf.Driver = uplink.NewAFPacketDriver(params, intf, vpp.log.WithFields(logrus.Fields{
		"subcomponent": "driver",
	}))

	config.NodeName = config.String("NodeName")
	config.ConfigTemplateEnvVar = config.String(`
		unix { nodaemon cli-listen /var/run/vpp/cli.sock }
        cpu { workers 0 }
        socksvr { socket-name /var/run/vpp/vpp-api.sock }
  		buffers { buffers-per-numa 2048 page-size 4K }
        plugins {
          plugin default { enable }
          plugin dpdk_plugin.so { disable }
          plugin ping_plugin.so { disable }
        }`)

	vpp.log.Debug("Loading config")
	_ = config.LoadConfigSilent(vpp.log) // we expect failure due to missing envvars

	vpp.log.Debug("Creating VppRunner")
	vpp.runner = NewVPPRunner(params, vpp.log.WithFields(logrus.Fields{
		"subcomponent": "vppmgm",
	}))

	vpp.log.Debug("Running VppRunner")
	err = vpp.runner.Run(vpp.ctx, vpp.vppIsRunningChan)
	if err != nil {
		vpp.log.Errorf("VppRunner exited to test with error %v", err)
		vpp.Err = err
	}
	vpp.log.Debug("VppRunner exited to test")
}