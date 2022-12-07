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
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/projectcalico/vpp-dataplane/config/config"
	"github.com/projectcalico/vpp-dataplane/config/startup"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/uplink"
	log "github.com/sirupsen/logrus"
)

var (
	runningCond *sync.Cond
	vppProcess  *os.Process
	vppDeadChan chan bool
	signals     chan os.Signal
	/* Was VPP terminated by us ? */
	internalKill bool
	/* Increasing index for timeout */
	currentVPPIndex int
	/* Allow to stop sigchld handling for given VPP */
	VPPgotSigCHLD map[int]bool
	/* Allow to stop timeouts for given VPP */
	VPPgotTimeout map[int]bool
)

func timeoutSigKill(vppIndex int) {
	time.Sleep(config.VppSigKillTimeout * time.Second)
	if VPPgotTimeout[vppIndex] {
		return
	}
	log.Infof("Timeout : SIGKILL vpp %d", vppIndex)
	signals <- syscall.SIGKILL
}

func terminateVpp(format string, args ...interface{}) {
	log.Errorf(format, args...)
	log.Infof("Terminating Vpp %d (SIGINT)", currentVPPIndex)
	internalKill = true
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
		}
		runningCond.L.Lock()
		for vppProcess == nil {
			runningCond.Wait()
		}
		log.Infof("Received signal %+v, vpp index %d", s, currentVPPIndex)
		if s == syscall.SIGCHLD {
			/* figure out pid of exited process */
			wstatus := syscall.WaitStatus(0)
			pid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG, nil)
			if err != nil {
				log.Errorf("Wait4 error: %v", err)
			} else if pid == vppProcess.Pid {
				/* Only allow one SIGCHLD per VPP */
				if !VPPgotSigCHLD[currentVPPIndex] {
					VPPgotSigCHLD[currentVPPIndex] = true
					vppDeadChan <- true
					err = vppProcess.Release()
					if err != nil {
						log.Warnf("Process release error: %v", err)
					}
					log.Infof("VPP exited:%v status:%v signaled:%v", wstatus.Exited(), wstatus.ExitStatus(), wstatus.Signaled())
					if wstatus.Signaled() {
						log.Infof("Termination signal: %v, core dumped:%v", wstatus.Signal(), wstatus.CoreDump())
					}
				} else {
					log.Warnf("This VPP already got a SIGCHLD!")
				}
			} else {
				log.Infof("Ignoring SIGCHLD for pid %d", pid)
			}
		} else if s != syscall.SIGPIPE {
			/* special case
			   for SIGTERM, which doesn't kill vpp quick enough */
			if s == syscall.SIGTERM {
				s = syscall.SIGINT
			}
			err := vppProcess.Signal(s)
			if err != nil {
				log.WithError(err).Warn("Process signal errord")
			}
			log.Infof("Signaled vpp (PID %d) %+v", vppProcess.Pid, s)
			if s == syscall.SIGINT || s == syscall.SIGQUIT {
				go timeoutSigKill(currentVPPIndex)
			}
		}
		log.Infof("Done with signal %+v", s)
		runningCond.L.Unlock()
	}
}

func makeNewVPPIndex() {
	/* No more notifications for previous VPP */
	runningCond.L.Lock()
	VPPgotSigCHLD[currentVPPIndex] = true
	VPPgotTimeout[currentVPPIndex] = true
	vppProcess = nil
	runningCond.L.Unlock()
	runningCond.Broadcast()

	currentVPPIndex += 1
	VPPgotSigCHLD[currentVPPIndex] = false
	VPPgotTimeout[currentVPPIndex] = false
}

func main() {
	vppDeadChan = make(chan bool, 1)
	VPPgotSigCHLD = make(map[int]bool)
	VPPgotTimeout = make(map[int]bool)

	params := startup.GetVppManagerParams()

	hooks.RunHook(hooks.BEFORE_IF_READ, params, nil)

	var confs = startup.PrepareConfiguration(params)

	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()

	startup.PrintVppManagerConfig(params, confs)

	runner := NewVPPRunner(params, confs)

	makeNewVPPIndex()

	if len(params.UplinksSpecs) == 1 && params.UplinksSpecs[0].VppDriver == "" {
		for _, driver := range uplink.SupportedUplinkDrivers(params, confs[0], &params.UplinksSpecs[0]) {
			err := startup.CleanupCoreFiles(params.CorePattern)
			if err != nil {
				log.Errorf("CleanupCoreFiles errored %s", err)
			}

			internalKill = false
			err = runner.Run([]uplink.UplinkDriver{driver})
			if err != nil {
				hooks.RunHook(hooks.VPP_ERRORED, params, confs)
				log.Errorf("VPP(%s) run failed with %s", driver.GetName(), err)
			}
			if vppProcess != nil && !internalKill {
				log.Infof("External Kill")
				/* Don't restart VPP if we were asked to terminate */
				break
			}
			makeNewVPPIndex()
		}
	} else {
		err := startup.CleanupCoreFiles(params.CorePattern)
		if err != nil {
			log.Errorf("CleanupCoreFiles errored %s", err)
		}

		var drivers []uplink.UplinkDriver
		for idx := 0; idx < len(params.UplinksSpecs); idx++ {
			drivers = append(drivers, uplink.NewUplinkDriver(params.UplinksSpecs[idx].VppDriver,
				params, confs[idx], &params.UplinksSpecs[idx]))
		}

		err = runner.Run(drivers)
		if err != nil {
			hooks.RunHook(hooks.VPP_ERRORED, params, confs)
			log.Errorf("VPP run failed with %v", err)
		}

	}

}
