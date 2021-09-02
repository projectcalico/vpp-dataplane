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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/startup"
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
	/* Allow a maximum number of corefiles, delete older ones */
	maxCoreFiles = 5

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
			vppProcess.Signal(s)
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

type timeSlice []time.Time

func (s timeSlice) Less(i, j int) bool { return s[i].Before(s[j]) }
func (s timeSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s timeSlice) Len() int           { return len(s) }

func cleanup_corefiles(corePattern string) error {
	files := make(map[time.Time]string)
	var times timeSlice = []time.Time{}
	dir := corePattern[:strings.LastIndex(corePattern, "/")]
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if path != dir {
			files[info.ModTime()] = path
			times = append(times, info.ModTime())
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(files) > maxCoreFiles {
		sort.Sort(times)
		for _, time := range times[:len(times)-maxCoreFiles] {
			os.Remove(files[time])
		}
	}
	return nil
}

func main() {
	vppDeadChan = make(chan bool, 1)
	VPPgotSigCHLD = make(map[int]bool)
	VPPgotTimeout = make(map[int]bool)

	params := startup.GetVppManagerParams()

	cleanup_corefiles(params.CorePattern)
	hooks.RunHook(hooks.BEFORE_IF_READ, params, nil)
	conf := startup.PrepareConfiguration(params)

	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()

	startup.PrintVppManagerConfig(params, conf)

	runner := NewVPPRunner(params, conf)

	makeNewVPPIndex()
	if params.NativeDriver == "" {
		for _, driver := range uplink.SupportedUplinkDrivers(params, conf) {
			internalKill = false
			err := runner.Run(driver)
			if err != nil {
				hooks.RunHook(hooks.VPP_ERRORED, params, conf)
				log.Errorf("VPP(%s) run failed with %s", driver, err)
			}
			if vppProcess != nil && !internalKill {
				log.Infof("External Kill")
				/* Don't restart VPP if we were asked to terminate */
				break
			}
			makeNewVPPIndex()
		}
	} else {
		driver := uplink.NewUplinkDriver(params.NativeDriver, params, conf)
		err := runner.Run(driver)
		if err != nil {
			hooks.RunHook(hooks.VPP_ERRORED, params, conf)
			log.Errorf("VPP(%s) run failed with %s", params.NativeDriver, err)
		}
	}
}
