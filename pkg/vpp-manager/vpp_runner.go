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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/hooks"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpplink"
	"github.com/sirupsen/logrus"
)

type VppRunner struct {
	log            *logrus.Entry
	params         *params.VppManagerParams
	vpp            *vpplink.VppLink
	VppManagerInfo *config.VppManagerInfo
	networkHook    *hooks.NetworkManagerHook

	vppProcess     *os.Process
	vppSignals     chan os.Signal
	vppRunningCond *sync.Cond
}

func NewVPPRunner(params *params.VppManagerParams, log *logrus.Entry) *VppRunner {
	return &VppRunner{
		log:    log,
		params: params,
		VppManagerInfo: &config.VppManagerInfo{
			UplinkStatuses: make(map[string]config.UplinkStatus),
			PhysicalNets: map[string]config.PhysicalNetwork{
				config.DefaultPhysicalNetworkName: {
					VrfID:    config.DefaultVRFIndex,
					PodVrfID: config.PodVRFIndex,
				},
			},
		},
		networkHook:    hooks.NewNetworkManagerHook(log, params),
		vppSignals:     make(chan os.Signal, 10),
		vppRunningCond: sync.NewCond(&sync.Mutex{}),
	}
}

func (v *VppRunner) vppSignalHandler(callerCtx context.Context, wg *sync.WaitGroup) context.Context {
	var callerDoneOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())

	signal.Notify(v.vppSignals)
	signal.Reset(syscall.SIGURG)
	signal.Reset(syscall.SIGUSR2)

	config.HandleUsr2Signal(ctx, v.log.WithFields(logrus.Fields{"component": "sighdlr"}))

	wg.Go(func() {
		for {
			select {
			case <-callerCtx.Done():
				callerDoneOnce.Do(func() {
					v.log.Infof("Caller asked for termination, using sigint")
					v.vppSignals <- syscall.SIGINT
				})
			case <-ctx.Done():
				return
			case sig := <-v.vppSignals:
				// Use an inline func with defer so every exit path
				// (including SIGCHLD short-circuits) releases the lock.
				// Without this, a `continue`/`return` inside the switch
				// would skip Unlock() and deadlock on the next signal.
				func() {
					v.vppRunningCond.L.Lock()
					defer v.vppRunningCond.L.Unlock()
					for v.vppProcess == nil {
						v.vppRunningCond.Wait()
					}
					v.log.Infof("Received signal %s", sig)
					switch sig {
					case syscall.SIGCHLD:
						/* figure out pid of exited process */
						wstatus := syscall.WaitStatus(0)
						pid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG, nil)
						if err != nil {
							v.log.Errorf("Wait4 error: %v", err)
							return
						}
						if pid != v.vppProcess.Pid {
							v.log.Infof("Ignoring SIGCHLD for pid %d", pid)
							return
						}
						cancel()
						err = v.vppProcess.Release()
						if err != nil {
							v.log.Warnf("Process release error: %v", err)
						}
						v.log.Infof("VPP exited:%v status:%v signaled:%v",
							wstatus.Exited(), wstatus.ExitStatus(), wstatus.Signaled())
						if wstatus.Signaled() {
							v.log.Infof("Termination signal: %v, core dumped:%v",
								wstatus.Signal(), wstatus.CoreDump())
						}
					case syscall.SIGPIPE:
						// nothing
					case syscall.SIGTERM:
						// promote SIGTERM to SIGINT so that we do terminate
						// VPP on SIGTERMs
						sig = syscall.SIGINT
						fallthrough
					case syscall.SIGINT, syscall.SIGQUIT:
						wg.Go(func() {
							select {
							case <-ctx.Done():
							case <-time.After(config.VppSigKillTimeout * time.Second):
								v.log.Infof("Timeout: sending SIGKILL to vpp")
								err := v.vppProcess.Signal(syscall.SIGKILL)
								if err != nil {
									v.log.WithError(err).Warn("err sending sigkill to vpp")
								}
								cancel()
							}
						})
						fallthrough
					default:
						v.log.Infof("sending signal %s to vpp pid %d", sig, v.vppProcess.Pid)
						err := v.vppProcess.Signal(sig)
						if err != nil {
							v.log.WithError(err).Warnf("err sending signal %s to vpp", sig)
						}
					}
				}()
			}
		}
	})

	return ctx
}

func (v *VppRunner) Run(callerCtx context.Context, vppIsRunningChan chan bool) error {
	var wg sync.WaitGroup
	// Close vppIsRunningChan exactly once; consumers (e.g. the parent
	// goroutine that waits for VPP readiness) must not block forever
	// if Run() exits early because of a setup failure.
	var closeVppIsRunningOnce sync.Once
	closeVppIsRunning := func() { closeVppIsRunningOnce.Do(func() { close(vppIsRunningChan) }) }
	defer func() {
		v.log.Infof("Waiting for signal handler teardown")
		closeVppIsRunning()
		wg.Wait()
		v.log.Infof("VppRunner exited")
	}()
	v.networkHook.ExecuteWithUserScript(hooks.HookBeforeIfRead, config.HookScriptBeforeIfRead)

	err := config.ClearVppManagerFiles()
	if err != nil {
		return errors.Wrap(err, "Error clearing config files")
	}

	err = config.SetCorePattern(config.GetCalicoVppInitialConfig().CorePattern)
	if err != nil {
		v.log.Fatalf("Error setting core pattern: %s", err)
	}

	err = config.SetRLimitMemLock()
	if err != nil {
		v.log.Errorf("Error raising memlock limit, VPP may fail to start: %v", err)
	}

	ctx := v.vppSignalHandler(callerCtx, &wg)

	v.params.PrintVppManagerConfig()

	err = config.CleanupCoreFiles(v.log, config.GetCalicoVppInitialConfig().CorePattern, config.DefaultMaxCoreFiles)
	if err != nil {
		v.log.Errorf("CleanupCoreFiles errored %s", err)
	}

	// Iterate the ordered slice (InterfacesByID), not the Interfaces map.
	// Map iteration is non-deterministic in Go; UpdateVppConfigFile and
	// driver Preconfigure/Restore steps can be order-sensitive for multi-
	// uplink configurations.
	for _, intf := range v.params.InterfacesByID {
		v.log.Infof("Running interface %s with uplink %s", intf.Spec.InterfaceName, intf.Driver.GetName())
	}
	template := v.params.TemplateScriptReplace(*config.ConfigExecTemplateEnvVar)
	err = os.WriteFile(v.params.VppConfigExecFile, []byte(template+"\n"), 0744)
	if err != nil {
		return errors.Wrapf(err, "Error writing VPP config exec file to %s", v.params.VppConfigExecFile)
	}

	template = v.params.TemplateScriptReplace(*config.ConfigTemplateEnvVar)
	for _, intf := range v.params.InterfacesByID {
		template = intf.Driver.UpdateVppConfigFile(template)
	}
	err = os.WriteFile(v.params.VppConfigFile, []byte(template+"\n"), 0644)
	if err != nil {
		return errors.Wrapf(err, "Error writing VPP config file to %s", v.params.VppConfigFile)
	}

	for _, intf := range v.params.InterfacesByID {
		err = intf.Driver.PreconfigureLinux()
		if err != nil {
			return errors.Wrapf(err, "Error pre-configuring Linux main IF: %s", intf.Driver.GetName())
		}
	}

	v.networkHook.ExecuteWithUserScript(hooks.HookBeforeVppRun, config.HookScriptBeforeVppRun)

	if !v.params.AllInterfacesPhysical() { // use separate net namespace because linux deletes these interfaces when ns is deleted
		if ns.IsNSorErr(config.GetnetnsPath(config.VppNetnsName)) != nil {
			_, err = config.NewNS(config.VppNetnsName)
			if err != nil {
				return errors.Wrap(err, "Could not add VPP netns")
			}
		}

		/**
		 * Run VPP in an isolated network namespace, used to park the interface
		 * in af_packet or af_xdp mode */
		err = ns.WithNetNSPath(config.GetnetnsPath(config.VppNetnsName), func(ns.NetNS) (err error) {
			vppCmd := exec.Command(v.params.VppPath, "-c", v.params.VppConfigFile)
			vppCmd.Stdout = os.Stdout
			vppCmd.Stderr = os.Stderr
			err = vppCmd.Start()
			if err != nil {
				return err
			}
			v.vppProcess = vppCmd.Process
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "Error starting vpp process")
		}
	} else { // use vpp own net namespace
		// From this point it is very important that every exit path calls restoreConfiguration after vpp exits
		vppCmd := exec.Command(v.params.VppPath, "-c", v.params.VppConfigFile)
		vppCmd.SysProcAttr = &syscall.SysProcAttr{
			// Run VPP in an isolated network namespace, used to park the interface in
			// af_packet or af_xdp mode
			Cloneflags: syscall.CLONE_NEWNET,
		}
		vppCmd.Stdout = os.Stdout
		vppCmd.Stderr = os.Stderr
		err = vppCmd.Start()

		if err != nil {
			return errors.Wrap(err, "Error starting vpp process")
		}
		v.vppProcess = vppCmd.Process
	}

	defer func() {
		if r := recover(); r != nil {
			// we recover and log the error if there is a bug in vpp-manager
			err = fmt.Errorf("recovered error in vpp-manager: %v", r)
		}
		if err != nil {
			v.log.WithError(err).Error("sending SIGINT to vpp")
			v.vppSignals <- syscall.SIGINT
			<-ctx.Done()
			v.networkHook.ExecuteWithUserScript(hooks.HookVppErrored, config.HookScriptVppErrored)
		}
		v.log.Infof("Restoring configuration")
		if cleanupErr := config.ClearVppManagerFiles(); cleanupErr != nil {
			v.log.Errorf("Error clearing vpp manager files: %v", cleanupErr)
		}
		for _, intf := range v.params.InterfacesByID {
			intf.Driver.RestoreLinux()
		}
		if pingErr := config.PingCalicoVpp(v.log); pingErr != nil {
			v.log.Errorf("Error pinging calico-vpp: %v", pingErr)
		}
	}()

	v.log.Infof("VPP started [PID %d]", v.vppProcess.Pid)
	v.vppRunningCond.Broadcast()

	/**
	* Ensure any stale Calico VPP agents are terminated by calling pingCalicoVPP().
	* This handles cases where a previous VPP instance was killed abruptly and
	* didn't restore its configuration.
	* Must be done before writing the info file to make sure the new agent
	* doesn't respond to SIGUSR1 and avoid killing it */
	err = config.PingCalicoVpp(v.log)
	if err != nil {
		v.log.Errorf("Error pinging calico-vpp: %v", err)
	}

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(config.GetCalicoVppInitialConfig().VppStartupSleepSeconds) * time.Second)

	err = v.doVppGlobalConfiguration()
	if err != nil {
		// If v.vpp is nil (VPP API connection failed) the next loop
		// panics on nil dereference; if v.vpp is non-nil but global
		// config (VRFs, punt, neighbours) is partial, subsequent
		// uplink configuration would either fail or, worse, succeed
		// against a misconfigured VPP and silently overwrite this
		// error to nil so the deferred cleanup wouldn't SIGINT VPP.
		return errors.Wrap(err, "Error configuring VPP")
	}

	for _, intf := range v.params.InterfacesByID {
		err = v.configureVppUplinkInterface(intf)
		if err != nil {
			return errors.Wrapf(err, "Error configuring VPP uplink %s", intf.Spec.InterfaceName)
		}
	}

	// Configure Linux side of tap interfaces BEFORE the VPP_RUNNING hook.
	// This brings the tap UP so the kernel generates its link-local addeess,
	// which we then reconcile to the physical link-local address in
	// configureIPv6LinkLocal() BEFORE restarting networkd in VPP_RUNNING.
	for _, intf := range v.params.InterfacesByID {
		err = v.configureLinuxTap(intf)
		if err != nil {
			return errors.Wrapf(err, "Error configuring VPP tap %s", intf.Spec.InterfaceName)
		}
	}

	// Discover IPv6 link-local addresses and configure punt table routes,
	// uplink addresses, and ND proxy. This runs after configureLinuxTap()
	// has brought the taps UP, so the kernel has generated the LL addresses.
	for _, intf := range v.params.InterfacesByID {
		err = v.configureIPv6LinkLocal(intf)
		if err != nil {
			return errors.Wrapf(err, "Error configuring VPP tap %s", intf.Spec.InterfaceName)
		}
	}

	v.networkHook.ExecuteWithUserScript(hooks.HookVppRunning, config.HookScriptVppRunning)

	// Set the TAP interfaces admin-up in VPP last, after all Linux-side
	// configuration is complete.
	for _, intf := range v.params.InterfacesByID {
		err = v.vpp.InterfaceAdminUp(intf.State.TapSwIfIndex)
		if err != nil {
			return err
		}
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = v.updateCalicoNode(v.params.InterfacesByID[0].State)
	if err != nil {
		return err
	}

	v.VppManagerInfo.Status = config.Ready
	file, err := json.MarshalIndent(v.VppManagerInfo, "", " ")
	if err != nil {
		return errors.Wrap(err, "Failed to encode json for info file")
	}
	err = os.WriteFile(config.VppManagerInfoFile, file, 0644)
	if err != nil {
		return errors.Wrap(err, "Error writing vpp manager file")
	}

	// close the vpp API chan as beyond this point VPP-manager will not interact with VPP anymore
	v.vpp.Close()

	closeVppIsRunning()
	<-ctx.Done()
	v.log.Infof("VPP Exited")

	v.networkHook.ExecuteWithUserScript(hooks.HookVppDoneOk, config.HookScriptVppDoneOk)
	return nil
}
