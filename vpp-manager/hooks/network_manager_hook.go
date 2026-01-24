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
	"path/filepath"
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
	IsAWS                bool
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

// isAWSEnvironment checks if we are running on AWS
func (h *NetworkManagerHook) isAWSEnvironment() bool {
	cmd := h.chrootCommand("dmidecode", "-s", "bios-vendor")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Amazon EC2")
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

	// Check if running on AWS
	if h.isAWSEnvironment() {
		h.systemType.IsAWS = true
		h.log.Info("NetworkManagerHook: Detected AWS environment")
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
		return h.restartService("systemd-networkd")
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

// hasInterfaceDynamicIP checks if interface has a dynamic IP address
func (h *NetworkManagerHook) hasInterfaceDynamicIP(interfaceName string) bool {
	cmd := h.chrootCommand("ip", "addr", "show", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check for "inet" using word boundary regex
	matched, err := regexp.MatchString(`\binet\b`, string(output))
	if err != nil || !matched {
		return false
	}

	// Check for "dynamic" keyword
	return strings.Contains(string(output), "dynamic")
}

// isInterfaceConfigured checks if interface is in configured state
func (h *NetworkManagerHook) isInterfaceConfigured(interfaceName string) bool {
	cmd := h.chrootCommand("networkctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, interfaceName) && strings.Contains(line, "configured") {
			return true
		}
	}
	return false
}

// isInterfaceUnmanaged checks if interface is in unmanaged state
func (h *NetworkManagerHook) isInterfaceUnmanaged(interfaceName string) bool {
	cmd := h.chrootCommand("networkctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, interfaceName) && strings.Contains(line, "unmanaged") {
			return true
		}
	}
	return false
}

// getNetworkFilePath retrieves the path to the network file for the interface
func (h *NetworkManagerHook) getNetworkFilePath(interfaceName string) (string, error) {
	cmd := h.chrootCommand("networkctl", "status", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get networkctl status")
	}

	// Parse output to find "Network File:" line
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Network File:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Network File:"))
			// Prepend /host since we're in a container
			if !strings.HasPrefix(path, "/host") {
				path = filepath.Join("/host", path)
			}
			return path, nil
		}
	}

	return "", nil
}

// saveNetworkFile saves the network configuration file on AWS for a specific interface
func (h *NetworkManagerHook) saveNetworkFile(interfaceName string) error {
	if !h.systemType.IsAWS || !h.systemType.HasSystemdNetworkd {
		return nil
	}

	// Check if interface has dynamic IP
	if !h.hasInterfaceDynamicIP(interfaceName) {
		return nil
	}

	// Check if interface is configured
	if !h.isInterfaceConfigured(interfaceName) {
		return nil
	}

	// Get network file path
	networkFilePath, err := h.getNetworkFilePath(interfaceName)
	if err != nil {
		return err
	}

	if networkFilePath == "" {
		h.log.Warnf("NetworkManagerHook: Could not find network file path for %s", interfaceName)
		return nil
	}

	h.log.Infof("NetworkManagerHook: Saving network configuration file for %s...", interfaceName)

	// Save the original network file
	origPath := fmt.Sprintf("/tmp/%s.network.orig", interfaceName)
	content, err := os.ReadFile(networkFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to read network file %s", networkFilePath)
	}

	err = os.WriteFile(origPath, content, 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to save network file to %s", origPath)
	}

	h.log.Infof("NetworkManagerHook: Saved network file to %s", origPath)
	return nil
}

// tweakNetworkFile modifies the network configuration for unmanaged interfaces on AWS for a specific interface
func (h *NetworkManagerHook) tweakNetworkFile(interfaceName string) error {
	if !h.systemType.IsAWS || !h.systemType.HasSystemdNetworkd {
		return nil
	}

	// Check if interface has dynamic IP
	if !h.hasInterfaceDynamicIP(interfaceName) {
		return nil
	}

	// Check if interface is unmanaged
	if !h.isInterfaceUnmanaged(interfaceName) {
		return nil
	}

	h.log.Infof("NetworkManagerHook: uplink interface %s in unmanaged state; fixing...", interfaceName)

	origPath := fmt.Sprintf("/tmp/%s.network.orig", interfaceName)
	tmpPath := fmt.Sprintf("/tmp/%s.network", interfaceName)
	finalPath := fmt.Sprintf("/host/etc/systemd/network/%s.network", interfaceName)

	// Read original file
	content, err := os.ReadFile(origPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read original network file")
	}

	// Remove [Match] section from original content
	lines := strings.Split(string(content), "\n")
	var filteredLines []string
	inMatchSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[Match]") {
			inMatchSection = true
			continue
		}
		if inMatchSection && (strings.HasPrefix(trimmed, "[") || trimmed == "") {
			inMatchSection = false
			if trimmed == "" {
				continue
			}
		}
		if !inMatchSection {
			filteredLines = append(filteredLines, line)
		}
	}

	// Create new content with new [Match] section
	newContent := fmt.Sprintf("[Match]\nName=%s\n\n%s", interfaceName, strings.Join(filteredLines, "\n"))

	// Write temporary file
	err = os.WriteFile(tmpPath, []byte(newContent), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write temporary network file")
	}

	// Copy to final location
	err = os.WriteFile(finalPath, []byte(newContent), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write final network file")
	}

	// Create marker file
	err = os.WriteFile("/host/var/run/vpp/network_file_tweaked", []byte{}, 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to create marker file")
	}

	// Clean up temporary files
	err = os.Remove(tmpPath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to remove temporary network file")
	}
	err = os.Remove(origPath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to remove original network file")
	}

	// Restart systemd-networkd
	return h.restartService("systemd-networkd")
}

// removeTweakedNetworkFile removes the tweaked network configuration for a specific interface
func (h *NetworkManagerHook) removeTweakedNetworkFile(interfaceName string) error {
	markerPath := "/host/var/run/vpp/network_file_tweaked"
	_, err := os.Stat(markerPath)
	if os.IsNotExist(err) {
		return nil
	}

	h.log.Infof("NetworkManagerHook: Deleting tweaked network file for %s...", interfaceName)

	networkFilePath := fmt.Sprintf("/host/etc/systemd/network/%s.network", interfaceName)
	err = os.Remove(networkFilePath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to remove network file")
	}

	err = os.Remove(markerPath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to remove marker file")
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

// createUdevNetNameRules creates udev rules to restore ID_NET_NAME_* properties for all interfaces
// This must be called AFTER VPP has taken over the interfaces and created the taps
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

		// Each interface gets its own rule line
		ruleBuilder.WriteString(fmt.Sprintf("ACTION==\"add\", SUBSYSTEM==\"net\", ATTR{address}==\"%s\"", props.MacAddress))

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

	// Reload udev rules
	cmd := h.chrootCommand("udevadm", "control", "--reload-rules")
	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to reload udev rules: %v", err)
	}

	// Trigger udev for net subsystem to apply the stored ID_NET_NAME_* properties
	cmd = h.chrootCommand("udevadm", "trigger", "--subsystem-match=net", "--action=add")
	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to trigger udev: %v", err)
	}
	h.log.Info("NetworkManagerHook: Triggered udev to apply the stored ID_NET_NAME_* properties")

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

	// Save network file for AWS systemd-networkd for each interface
	for _, interfaceName := range h.interfaceNames {
		err = h.saveNetworkFile(interfaceName)
		if err != nil {
			return err
		}
	}

	return nil
}

// vppRunning handles tasks while VPP is running
func (h *NetworkManagerHook) vppRunning() error {
	// Create udev rules to restore ID_NET_NAME_* properties for all interfaces
	// This must happen after VPP has created the tap/tun interfaces with the original MACs
	err := h.createUdevNetNameRules()
	if err != nil {
		h.log.Warnf("NetworkManagerHook: Failed to create udev rules: %v", err)
	}

	// Restart network services
	err = h.restartNetwork()
	if err != nil {
		return err
	}

	// Tweak network file for AWS systemd-networkd for each interface
	for _, interfaceName := range h.interfaceNames {
		err = h.tweakNetworkFile(interfaceName)
		if err != nil {
			return err
		}
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

	// Remove the tweaked network file for AWS systemd-networkd for each interface
	for _, interfaceName := range h.interfaceNames {
		err = h.removeTweakedNetworkFile(interfaceName)
		if err != nil {
			return err
		}
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
