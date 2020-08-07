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
}

type CalicoVppServerData struct{}

func (*CalicoVppServerData) BarrierSync() {
	barrierCond.L.Lock()
	for barrier {
		barrierCond.Wait()
	}
	barrierCond.L.Unlock()
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

func HandleVppManagerRestart(log *logrus.Logger, vpp *vpplink.VppLink, servers ...CalicoVppServer) {
	barrierCond = sync.NewCond(&sync.Mutex{})
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGUSR1)
	for {
		<-signals
		WaitForVppManager()
		log.Infof("SR:Vpp restarted")
		barrier = true
		err := vpp.Reconnect()
		if err != nil {
			log.Errorf("Reconnection failed %v", err)
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
