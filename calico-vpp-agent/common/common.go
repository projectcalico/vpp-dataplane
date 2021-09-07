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
	"fmt"
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

const (
	DefaultVRFIndex     = uint32(0)
	PuntTableId         = uint32(1)
	PodVRFIndex         = uint32(2)
)

type CalicoVppServer interface {
	/* Run the server */
	Serve()
	/* Stop the server */
	Stop()
	/* Sync to ensure server pauses when OnVppRestart is called */
	BarrierSync()
	/* Called when VPP signals us that it has restarted */
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
	barrier = false
	barrierCond = sync.NewCond(&sync.Mutex{})
}

func HandleVppManagerRestart(log *logrus.Logger, vpp *vpplink.VppLink, servers ...CalicoVppServer) {
	barrierCond.L.Lock()
	barrier = false
	barrierCond.L.Unlock()
	barrierCond.Broadcast()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGUSR1)
	for {
		<-signals
		log.Infof("SR:Vpp restarted")
		barrierCond.L.Lock()
		barrier = true
		barrierCond.L.Unlock()
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
		err = SetupPodVRF(vpp)
		if err != nil {
			log.Fatalf("Error reconfiguring pod vrf in VPP: %v", err)
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

func SetupPodVRF(vpp *vpplink.VppLink) (err error) {
	for _, ipFamily := range vpplink.IpFamilies {
		err = vpp.AddVRF(PodVRFIndex, ipFamily.IsIp6, fmt.Sprintf("calico-pods-%s", ipFamily.Str))
		if err != nil {
			return err
		}
		err = vpp.AddDefaultRouteViaTable(PodVRFIndex, DefaultVRFIndex, ipFamily.IsIp6)
		if err != nil {
			return err
		}
	}
	return nil
}

func SafeFormat(e interface{ String() string }) string {
	if e == nil {
		return ""
	} else {
		return e.String()
	}
}

func FormatSlice(lst []interface{ String() string }) string {
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

func GetMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func ToMaxLenCIDR(addr net.IP) *net.IPNet {
	return &net.IPNet{
		IP:   addr,
		Mask: GetMaxCIDRMask(addr),
	}
}

func FullyQualified(addr net.IP) *net.IPNet {
	return &net.IPNet{
		IP:   addr,
		Mask: GetMaxCIDRMask(addr),
	}
}

// This function and the related mechanism in vpmanager are curently kept around
// in case they're useful for the Host Endpoint policies implementation
func GetVppTapSwifIndex() (swIfIndex uint32, err error) {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerTapIdxFile)
		if err == nil {
			idx, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 32)
			if err == nil && idx != -1 {
				return uint32(idx), nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return 0, errors.Errorf("Vpp-host tap not ready after 20 tries")
}
