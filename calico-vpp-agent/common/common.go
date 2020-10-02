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

package common

import (
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

var (
	barrier     bool
	barrierCond *sync.Cond
)

type Stringable interface {
	String() string
}

type CalicoVppServer interface {
	BarrierSync()
	OnVppRestart()
	RescanState() error
}

type CalicoVppServerData struct{}

func (*CalicoVppServerData) BarrierSync() {
	barrierCond.L.Lock()
	for barrier {
		barrierCond.Wait()
	}
	barrierCond.L.Unlock()
}

func CreateVppLink(socket string, log *logrus.Entry) (vpp *vpplink.VppLink, err error) {
	// Get an API connection, with a few retries to accomodate VPP startup time
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(socket, log)
		if err != nil {
			log.Warnf("Try [%d/10] %v", i, err)
			err = nil
			time.Sleep(2 * time.Second)
		} else {
			return vpp, nil
		}
	}
	return nil, errors.Errorf("Cannot connect to VPP after 10 tries")
}

func WaitForVppManager() error {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerStatusFile)
		if err == nil && strings.TrimSpace(string(dat[:])) == "1" {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return errors.Errorf("Vpp manager not ready after 20 tries")
}

func WritePidToFile() error {
	pid := strconv.FormatInt(int64(os.Getpid()), 10)
	return ioutil.WriteFile(config.CalicoVppPidFile, []byte(pid+"\n"), 0400)
}

func InitRestartHandler() {
	barrierCond = sync.NewCond(&sync.Mutex{})
}

func HandleVppManagerRestart(log *logrus.Logger, vpp *vpplink.VppLink, servers ...CalicoVppServer) {
	barrier = true
	barrierCond.L.Lock()
	barrier = false
	barrierCond.L.Unlock()
	barrierCond.Broadcast()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	for {
		s := <-signals
		if s == syscall.SIGUSR2 {
			log.Infof("SIGUSR2")
			for i, srv := range servers {
				srv.RescanState()
				log.Infof("SR:server %d rescanned", i)
			}
			continue
		}
		log.Infof("SR:Vpp restarted")
		barrier = true
		vpp.Close()
		// Start by reconnecting to VPP to ensure vpp (and so vpp-manager) are running
		err := vpp.Retry(time.Second, 20, vpp.Reconnect)
		if err != nil {
			log.Errorf("Reconnection failed after 20 tries %v", err)
		}
		err = WaitForVppManager()
		if err != nil {
			log.Fatalf("Timed out waiting for vpp-manager: %v", err)
			os.Exit(1)
		}
		for i, srv := range servers {
			srv.OnVppRestart()
			log.Infof("SR:server %d restarted", i)
		}
		barrierCond.L.Lock()
		barrier = false
		barrierCond.L.Unlock()
		barrierCond.Broadcast()
	}
}

func SafeFormat(e Stringable) string {
	if e == nil {
		return ""
	} else {
		return e.String()
	}
}

func FormatSlice(lst []Stringable) string {
	strLst := make([]string, 0, len(lst))
	for _, e := range lst {
		strLst = append(strLst, e.String())
	}
	return strings.Join(strLst, ", ")
}

func getMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func getMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func FullyQualified(addr net.IP) *net.IPNet {
	return &net.IPNet{
		IP:   addr,
		Mask: getMaxCIDRMask(addr),
	}
}
