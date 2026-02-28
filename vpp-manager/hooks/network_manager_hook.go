// Copyright (C) 2024 Cisco Systems Inc.
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

package hooks

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/sirupsen/logrus"
)

// HookPoint represents the different stages at which hooks can be executed
type HookPoint string

const (
	HookBeforeIfRead HookPoint = "BEFORE_IF_READ"
	HookBeforeVppRun HookPoint = "BEFORE_VPP_RUN"
	HookVppRunning   HookPoint = "VPP_RUNNING"
	HookVppDoneOk    HookPoint = "VPP_DONE_OK"
	HookVppErrored   HookPoint = "VPP_ERRORED"

	// UdevRuleFilePath is the path to the udev rule file for restoring ID_NET_NAME_* properties
	UdevRuleFilePath = "/host/etc/udev/rules.d/99-vpp-restore-id_net_name.rules"
)

// SystemType represents different system configurations
type SystemType struct {
	HasSystemd           bool
	HasSystemdNetworkd   bool
	HasNetworkManager    bool
	HasNetworkingService bool
	HasNetworkService    bool
}

// UdevNetNameProperties stores udev network naming properties for an interface
type UdevNetNameProperties struct {
	MacAddress       string
	IDNetNameOnboard string
	IDNetNameSlot    string
	IDNetNamePath    string
	IDNetNameMac     string
}

// NetworkManagerHook manages network configuration during VPP lifecycle
type NetworkManagerHook struct {
	interfaceNames []string
	systemType     SystemType
	log            *logrus.Logger
	udevProps      map[string]*UdevNetNameProperties // map[interfaceName] -> udev properties
}

// chrootCommand creates a command that will be executed in the host namespace
func (h *NetworkManagerHook) chrootCommand(name string, args ...string) *exec.Cmd {
	shellCmd := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	return exec.Command("/usr/sbin/chroot", "/host", "/bin/sh", "-c", shellCmd)
}

// isServiceActive checks if a systemd service is active
func (h *NetworkManagerHook) isServiceActive(serviceName string) bool {
	cmd := h.chrootCommand("systemctl", "status", serviceName)
	err := cmd.Run()
	return err == nil
}

// detectSystem determines the type of system we are running on
func (h *NetworkManagerHook) detectSystem() {
	h.log.Info("NetworkManagerHook: Detecting system configuration...")

	// Check for systemd using chrootCommand
	cmd := h.chrootCommand("which", "systemctl")
	err := cmd.Run()
	if err == nil {
		h.systemType.HasSystemd = true
		h.log.Info("NetworkManagerHook: Detected systemd")
	}

	if !h.systemType.HasSystemd {
		h.log.Warn("NetworkManagerHook: Init system not supported, network configuration may fail")
		return
	}

	// Check for systemd-networkd using isServiceActive
	if h.isServiceActive("systemd-networkd") {
		h.systemType.HasSystemdNetworkd = true
		h.log.Info("NetworkManagerHook: Detected systemd-networkd")
	}

	// Check for NetworkManager
	if h.isServiceActive("NetworkManager") {
		h.systemType.HasNetworkManager = true
		h.log.Info("NetworkManagerHook: Detected NetworkManager")
	}

	// Check for networking service
	if h.isServiceActive("networking") {
		h.systemType.HasNetworkingService = true
		h.log.Info("NetworkManagerHook: Detected networking service")
	}

	// Check for network service
	if h.isServiceActive("network") {
		h.systemType.HasNetworkService = true
		h.log.Info("NetworkManagerHook: Detected network service")
	}

	if !h.systemType.HasSystemdNetworkd && !h.systemType.HasNetworkManager &&
		!h.systemType.HasNetworkingService && !h.systemType.HasNetworkService {
		h.log.Warn("NetworkManagerHook: Networking backend not detected, network configuration may fail")
	}
}

// restartService restarts a systemd service
func (h *NetworkManagerHook) restartService(serviceName string) error {
	cmd := h.chrootCommand("systemctl", "daemon-reload")
	err := cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to run daemon-reload")
	}

	cmd = h.chrootCommand("systemctl", "restart", serviceName)
	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to restart %s", serviceName)
	}

	return nil
}

// restartSystemdNetworkd restarts systemd-udev-trigger before restarting systemd-networkd.
func (h *NetworkManagerHook) restartSystemdNetworkd() error {
	err := h.restartService("systemd-udev-trigger")
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to restart systemd-udev-trigger before systemd-networkd: %v", err)
	}

	// Wait for udev to finish processing net events so systemd-networkd
	// can compute DHCPv6 IAID from restored ID_NET_NAME_* properties.
	cmd := h.chrootCommand("udevadm", "settle", "--timeout=5")
	if err := cmd.Run(); err != nil {
		h.log.Errorf("NetworkManagerHook: ERROR: udevadm settle timed out: %v", err)
	}

	return h.restartService("systemd-networkd")
}

// NewNetworkManagerHook creates a new NetworkManagerHook instance
func NewNetworkManagerHook(log *logrus.Logger) *NetworkManagerHook {
	hook := &NetworkManagerHook{
		log:       log,
		udevProps: make(map[string]*UdevNetNameProperties),
	}

	hook.detectSystem()
	return hook
}

// SetInterfaceNames updates the interface names of NetworkManagerHook instance
func (h *NetworkManagerHook) SetInterfaceNames(interfaceNames []string) {
	h.interfaceNames = interfaceNames
	h.log.Infof("NetworkManagerHook: Interface names updated to %v", interfaceNames)
}

// fixDNS modifies NetworkManager configuration to disable DNS management
func (h *NetworkManagerHook) fixDNS() error {
	if !h.systemType.HasNetworkManager {
		return nil
	}

	h.log.Info("NetworkManagerHook: System is using NetworkManager; fixing DNS...")

	nmConfPath := "/host/etc/NetworkManager/NetworkManager.conf"

	// Read the file
	content, err := os.ReadFile(nmConfPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read NetworkManager.conf")
	}

	// Check if dns=none is already present
	if strings.Contains(string(content), "dns=none") {
		h.log.Info("NetworkManagerHook: dns=none already present in NetworkManager.conf")
		return nil
	}

	// Add dns=none after [main] section
	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		newLines = append(newLines, line)
		if strings.TrimSpace(line) == "[main]" {
			newLines = append(newLines, "dns=none")
		}
	}

	// Update the file
	newContent := strings.Join(newLines, "\n")
	err = os.WriteFile(nmConfPath, []byte(newContent), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write NetworkManager.conf")
	}

	// Restart NetworkManager
	return h.restartService("NetworkManager")
}

// undoDNSFix removes the dns=none configuration from NetworkManager
func (h *NetworkManagerHook) undoDNSFix() error {
	if !h.systemType.HasNetworkManager {
		return nil
	}

	h.log.Info("NetworkManagerHook: System is using NetworkManager; undoing DNS fix...")

	nmConfPath := "/host/etc/NetworkManager/NetworkManager.conf"

	// Read the file
	content, err := os.ReadFile(nmConfPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read NetworkManager.conf")
	}

	// Remove dns=none
	re := regexp.MustCompile(`(?m)^dns=none\n?`)
	newContent := re.ReplaceAllString(string(content), "")

	// Update the file
	err = os.WriteFile(nmConfPath, []byte(newContent), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write NetworkManager.conf")
	}

	// Restart NetworkManager
	return h.restartService("NetworkManager")
}

// restartNetwork restarts the appropriate network service
func (h *NetworkManagerHook) restartNetwork() error {
	if h.systemType.HasSystemdNetworkd {
		h.log.Info("NetworkManagerHook: System is using systemd-networkd; restarting...")
		return h.restartSystemdNetworkd()
	} else if h.systemType.HasNetworkManager {
		h.log.Info("NetworkManagerHook: System is using NetworkManager; restarting...")
		return h.restartService("NetworkManager")
	} else if h.systemType.HasNetworkingService {
		h.log.Info("NetworkManagerHook: System is using networking service; restarting...")
		return h.restartService("networking")
	} else if h.systemType.HasNetworkService {
		h.log.Info("NetworkManagerHook: System is using network service; restarting...")
		return h.restartService("network")
	} else {
		h.log.Warn("NetworkManagerHook: Networking backend not detected, network configuration may fail")
	}
	return nil
}

// captureHostUdevProps captures udev properties for all interfaces
// This must be called BEFORE VPP takes over the interfaces
func (h *NetworkManagerHook) captureHostUdevProps() error {
	if !*config.GetCalicoVppDebug().EnableUdevNetNameRules {
		h.log.Info("NetworkManagerHook: Skipping captureHostUdevProps (enableUdevNetNameRules=false)")
		return nil
	}
	h.udevProps = make(map[string]*UdevNetNameProperties)
	for _, interfaceName := range h.interfaceNames {
		err := h.captureUdevNetNameProperties(interfaceName)
		if err != nil {
			h.log.Warnf("NetworkManagerHook: Failed to capture udev properties for %s: %v", interfaceName, err)
		}
	}
	return nil
}

// captureUdevNetNameProperties captures udev network naming properties for an interface
// This must be called BEFORE VPP takes over the interface
func (h *NetworkManagerHook) captureUdevNetNameProperties(interfaceName string) error {
	h.log.Infof("NetworkManagerHook: Capturing udev net name properties for %s...", interfaceName)

	// Get udevadm info for the interface
	cmd := h.chrootCommand("udevadm", "info", fmt.Sprintf("/sys/class/net/%s", interfaceName))
	output, err := cmd.Output()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to get udevadm info for %s: %v", interfaceName, err)
		return nil
	}

	props := &UdevNetNameProperties{}
	hasAnyProperty := false

	// Parse the udevadm output for ID_NET_NAME_* properties
	extractUdevProp := func(line, key string) (string, bool) {
		idx := strings.Index(line, key+"=")
		if idx == -1 {
			return "", false
		}
		return strings.TrimSpace(line[idx+len(key)+1:]), true
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if value, found := extractUdevProp(line, "ID_NET_NAME_ONBOARD"); found {
			props.IDNetNameOnboard = value
			hasAnyProperty = true
			h.log.Infof("NetworkManagerHook: Found ID_NET_NAME_ONBOARD=%s for %s", props.IDNetNameOnboard, interfaceName)
		} else if value, found := extractUdevProp(line, "ID_NET_NAME_SLOT"); found {
			props.IDNetNameSlot = value
			hasAnyProperty = true
			h.log.Infof("NetworkManagerHook: Found ID_NET_NAME_SLOT=%s for %s", props.IDNetNameSlot, interfaceName)
		} else if value, found := extractUdevProp(line, "ID_NET_NAME_PATH"); found {
			props.IDNetNamePath = value
			hasAnyProperty = true
			h.log.Infof("NetworkManagerHook: Found ID_NET_NAME_PATH=%s for %s", props.IDNetNamePath, interfaceName)
		} else if value, found := extractUdevProp(line, "ID_NET_NAME_MAC"); found {
			props.IDNetNameMac = value
			hasAnyProperty = true
			h.log.Infof("NetworkManagerHook: Found ID_NET_NAME_MAC=%s for %s", props.IDNetNameMac, interfaceName)
		}
	}

	if !hasAnyProperty {
		h.log.Infof("NetworkManagerHook: No udev net name properties found for %s", interfaceName)
		return nil
	}

	// Get MAC address from the interface
	cmd = h.chrootCommand("cat", fmt.Sprintf("/sys/class/net/%s/address", interfaceName))
	macOutput, err := cmd.Output()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to get MAC address for %s: %v", interfaceName, err)
		return nil
	}
	props.MacAddress = strings.TrimSpace(string(macOutput))
	if props.MacAddress == "" {
		h.log.Warnf("NetworkManagerHook: Failed to get MAC address for %s", interfaceName)
		return nil
	}
	h.log.Infof("NetworkManagerHook: Captured MAC address %s for %s", props.MacAddress, interfaceName)

	h.udevProps[interfaceName] = props
	return nil
}

// createUdevNetNameRules creates udev rules to restore ID_NET_NAME_* properties for all interfaces.
// This must be called BEFORE VPP creates host-facing taps so udev can re-apply the original
// ID_NET_NAME_* properties on net events (add/change/move re-evaluations).
func (h *NetworkManagerHook) createUdevNetNameRules() error {
	if !*config.GetCalicoVppDebug().EnableUdevNetNameRules {
		h.log.Info("NetworkManagerHook: Skipping createUdevNetNameRules (enableUdevNetNameRules=false)")
		return nil
	}
	// Build rules for all interfaces that have captured properties
	var ruleBuilder strings.Builder
	ruleBuilder.WriteString("# Re-apply ID_NET_NAME_* properties after Calico VPP creates the host-facing tap/tun netdev.\n")

	rulesAdded := 0
	for interfaceName, props := range h.udevProps {
		if props == nil || props.MacAddress == "" {
			h.log.Warnf("NetworkManagerHook: Skipping udev rule for %s - no MAC address captured", interfaceName)
			continue
		}

		h.log.Infof("NetworkManagerHook: Adding udev rule for %s with MAC %s", interfaceName, props.MacAddress)

		// Each interface gets its own rule line.
		// systemd-networkd uses ID_NET_NAME_* (via net_get_persistent_name) for DHCPv6 IAID
		// computation; without these properties it falls back to a MAC-derived IAID.
		ruleBuilder.WriteString(fmt.Sprintf("SUBSYSTEM==\"net\", ATTR{address}==\"%s\"", props.MacAddress))

		if props.IDNetNameOnboard != "" {
			ruleBuilder.WriteString(fmt.Sprintf(", ENV{ID_NET_NAME_ONBOARD}:=\"%s\"", props.IDNetNameOnboard))
		}
		if props.IDNetNameSlot != "" {
			ruleBuilder.WriteString(fmt.Sprintf(", ENV{ID_NET_NAME_SLOT}:=\"%s\"", props.IDNetNameSlot))
		}
		if props.IDNetNamePath != "" {
			ruleBuilder.WriteString(fmt.Sprintf(", ENV{ID_NET_NAME_PATH}:=\"%s\"", props.IDNetNamePath))
		}
		if props.IDNetNameMac != "" {
			ruleBuilder.WriteString(fmt.Sprintf(", ENV{ID_NET_NAME_MAC}:=\"%s\"", props.IDNetNameMac))
		}
		ruleBuilder.WriteString("\n")
		rulesAdded++
	}

	if rulesAdded == 0 {
		h.log.Warnf("NetworkManagerHook: No udev properties to create rules for, skipping")
		return nil
	}

	// Write the udev rule file
	err := os.WriteFile(UdevRuleFilePath, []byte(ruleBuilder.String()), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write udev rule file")
	}
	h.log.Infof("NetworkManagerHook: Created udev rule file at %s with %d rules", UdevRuleFilePath, rulesAdded)

	// Reload udev rules so the new rule is active for subsequent net events.
	cmd := h.chrootCommand("udevadm", "control", "--reload-rules")
	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to reload udev rules: %v", err)
	}
	h.log.Info("NetworkManagerHook: Reloaded udev rules")

	return nil
}

// removeUdevNetNameRules removes the udev rule file created for restoring ID_NET_NAME_* properties
func (h *NetworkManagerHook) removeUdevNetNameRules() error {
	if !*config.GetCalicoVppDebug().EnableUdevNetNameRules {
		h.log.Info("NetworkManagerHook: Skipping removeUdevNetNameRules (enableUdevNetNameRules=false)")
		return nil
	}
	_, err := os.Stat(UdevRuleFilePath)
	if os.IsNotExist(err) {
		return nil
	}

	h.log.Infof("NetworkManagerHook: Removing udev rule file %s...", UdevRuleFilePath)
	err = os.Remove(UdevRuleFilePath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to remove udev rule file")
	}

	// Reload udev rules after removal
	cmd := h.chrootCommand("udevadm", "control", "--reload-rules")
	err = cmd.Run()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to reload udev rules: %v", err)
	}

	// Trigger udev for net subsystem to remove the stored ID_NET_NAME_* properties
	cmd = h.chrootCommand("udevadm", "trigger", "--subsystem-match=net", "--action=change")
	err = cmd.Run()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to trigger udev: %v", err)
	}
	h.log.Info("NetworkManagerHook: Triggered udev to remove stored ID_NET_NAME_* properties")

	return nil
}

// beforeVppRun handles tasks before VPP starts
func (h *NetworkManagerHook) beforeVppRun() error {
	// Fix DNS configuration for NetworkManager
	err := h.fixDNS()
	if err != nil {
		return err
	}

	// Install udev rules before VPP creates taps so the tap "add" event gets
	// restored ID_NET_NAME_* and DHCPv6 IAID remains stable.
	err = h.createUdevNetNameRules()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to create udev rules: %v", err)
	}

	return nil
}

// vppRunning handles tasks while VPP is running
func (h *NetworkManagerHook) vppRunning() error {
	// Restart network services
	err := h.restartNetwork()
	if err != nil {
		return err
	}

	return nil
}

// vppDoneOk handles cleanup when VPP stops gracefully
func (h *NetworkManagerHook) vppDoneOk() error {
	// Remove the DNS fix for NetworkManager
	err := h.undoDNSFix()
	if err != nil {
		return err
	}

	// Remove the udev rule file for ID_NET_NAME_* restoration
	err = h.removeUdevNetNameRules()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to remove udev rule file: %v", err)
	}

	// Restart network services
	err = h.restartNetwork()
	if err != nil {
		return err
	}

	return nil
}

// vppErrored handles cleanup when VPP stops with an error
func (h *NetworkManagerHook) vppErrored() error {
	// same cleanup as vppDoneOk()
	return h.vppDoneOk()
}

// Execute runs the appropriate hook logic for the given hook point
func (h *NetworkManagerHook) Execute(hookPoint HookPoint) error {
	if !*config.EnableNetworkManagerHook {
		return nil
	}

	h.log.Infof("NetworkManagerHook: Executing %s for interfaces %v", hookPoint, h.interfaceNames)

	var err error
	switch hookPoint {
	case HookBeforeIfRead:
		err = h.captureHostUdevProps()
	case HookBeforeVppRun:
		err = h.beforeVppRun()
	case HookVppRunning:
		err = h.vppRunning()
	case HookVppDoneOk:
		err = h.vppDoneOk()
	case HookVppErrored:
		err = h.vppErrored()
	default:
		return fmt.Errorf("NetworkManagerHook: %s unknown hook point", hookPoint)
	}

	if err != nil {
		h.log.Warnf("NetworkManagerHook: %s errored with %v", hookPoint, err)
	}

	return err
}

// runGoNativeHook returns true when the Go-based native hook should execute.
// Go-based native hooks are skipped when a user script is configured or when
// they are explicitly disabled via CALICOVPP_ENABLE_NETWORK_MANAGER_HOOK=false.
func (h *NetworkManagerHook) runGoNativeHook(userHook *string) bool {
	if config.EnableNetworkManagerHook == nil || !*config.EnableNetworkManagerHook {
		return false
	}
	return userHook == nil || *userHook == ""
}

// useDefaultHookFallback returns true when we should use the legacy default_hook.sh
// This happens when: native hooks are disabled AND no user script is configured
func (h *NetworkManagerHook) useDefaultHookFallback(userHook *string) bool {
	if config.EnableNetworkManagerHook != nil && *config.EnableNetworkManagerHook {
		return false // Native hooks enabled, no fallback needed
	}
	// Native hooks disabled, use fallback only if no user script
	return userHook == nil || *userHook == ""
}

// ExecuteWithUserScript runs the appropriate hook based on configuration:
// 1. If user script configured -> run user script only (override)
// 2. If native hooks enabled -> run native Go hook
// 3. If native hooks disabled & no user script -> fallback to default_hook.sh
func (h *NetworkManagerHook) ExecuteWithUserScript(hookPoint HookPoint,
	hookScript *string,
	params *config.VppManagerParams) {
	// Check if user script is configured (highest priority - overrides everything)
	if hookScript != nil && *hookScript != "" {
		config.RunHook(hookScript, string(hookPoint), params, h.log)
		return
	}

	// Check if native Go hooks should run
	if h.runGoNativeHook(hookScript) {
		err := h.Execute(hookPoint)
		if err != nil {
			h.log.Warnf("Network hook %s failed: %v", hookPoint, err)
		}
		return
	}

	// Fallback to default_hook.sh when native hooks are disabled
	if h.useDefaultHookFallback(hookScript) {
		h.log.Infof("Native hooks disabled, falling back to default_hook.sh for %s", hookPoint)
		config.RunHook(&config.DefaultHookScript, string(hookPoint), params, h.log)
	}
}
