// Copyright (C) 2019 Cisco Systems Inc.
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

package main

import (
	"os"
	"os/exec"
	"sync"

	"os/signal"

	"syscall"

	"time"

	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/startup"
	log "github.com/sirupsen/logrus"
)

var (
	runningCond *sync.Cond
	vppCmd      *exec.Cmd
	vppProcess  *os.Process
	vppDeadChan chan bool
	vppAlive    bool
	signals     chan os.Signal
)

func timeOutSigKill() {
	time.Sleep(config.VppSigKillTimeout * time.Second)
	log.Infof("Timeout : SIGKILL vpp")
	signals <- syscall.SIGKILL
}

func terminateVpp(format string, args ...interface{}) {
	log.Errorf(format, args...)
	log.Infof("Terminating Vpp (SIGINT)")
	signals <- syscall.SIGINT
}

func handleSignals() {
	signals = make(chan os.Signal, 10)
	signal.Notify(signals)
	signal.Reset(syscall.SIGURG)
	for {
		s := <-signals
		if vppProcess == nil && s == syscall.SIGCHLD {
			/* Don't handle sigchld before vpp starts
			   There might still be a race condition if
			   vpp sefaults right on startup */
			continue
		} else if vppProcess == nil {
			runningCond.L.Lock()
			for vppProcess == nil {
				runningCond.Wait()
			}
			runningCond.L.Unlock()
		}
		log.Infof("Received signal %+v", s)
		if s == syscall.SIGCHLD {
			processState, err := vppCmd.Process.Wait()
			vppDeadChan <- true
			if err != nil {
				log.Errorf("processWait errored with %v", err)
			} else {
				log.Infof("processWait returned %v", processState)
			}
		} else {
			/* special case
			   for SIGTERM, which doesn't kill vpp quick enough */
			if s == syscall.SIGTERM {
				s = syscall.SIGINT
			}
			vppProcess.Signal(s)
			log.Infof("Signaled vpp (PID %d) %+v", vppProcess.Pid, s)
			if s == syscall.SIGINT || s == syscall.SIGQUIT || s == syscall.SIGSTOP {
				go timeOutSigKill()
			}
		}
		log.Infof("Done with signal %+v", s)
	}
}

func main() {
	vppDeadChan = make(chan bool, 1)
	vppAlive = false

	params, conf := startup.PrepareConfiguration()

	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()

	startup.PrintVppManagerConfig(params, conf)

	runner := NewVPPRunner(params, conf)
	runner.Run()

	return
}
