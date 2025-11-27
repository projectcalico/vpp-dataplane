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

package framework

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
	"github.com/sirupsen/logrus"
)

// VppInstance represents a VPP instance running in a Docker container
type VppInstance struct {
	Name          string
	ContainerName string
	Image         string
	Binary        string
	Config        VppConfig
	ExtraArgs     []string
	vppLink       *vpplink.VppLink
	log           *logrus.Entry
	socketPath    string
	isRunning     bool
}

// VppConfig holds VPP configuration parameters
type VppConfig struct {
	WorkersCount   int
	BuffersPerNuma int
	EnablePlugins  []string
	DisablePlugins []string
	CustomConfig   string
	UplinkConfig   *UplinkConfig
}

// UplinkConfig holds uplink interface configuration
type UplinkConfig struct {
	InterfaceName string
	IPv4Address   string
	IPv6Address   string
	IPv4Gateway   string
	IPv6Gateway   string
	MTU           int
}

// DefaultVppConfig returns a default VPP configuration suitable for testing
func DefaultVppConfig() VppConfig {
	return VppConfig{
		WorkersCount:   0,
		BuffersPerNuma: 131072,
		EnablePlugins:  []string{"dispatch_trace_plugin.so"},
		DisablePlugins: []string{"dpdk_plugin.so", "ping_plugin.so"},
	}
}

// NewVppInstance creates a new VPP instance with the given name and configuration
func NewVppInstance(name string, image string, binary string, config VppConfig, log *logrus.Logger) *VppInstance {
	if log == nil {
		log = logrus.New()
	}

	return &VppInstance{
		Name:          name,
		ContainerName: fmt.Sprintf("integration-test-vpp-%s", name),
		Image:         image,
		Binary:        binary,
		Config:        config,
		log:           log.WithFields(logrus.Fields{"vpp-instance": name}),
		socketPath:    fmt.Sprintf("/tmp/vpp-test-%s", name),
	}
}

// generateVppConfig generates VPP startup configuration
func (v *VppInstance) generateVppConfig() string {
	if v.Config.CustomConfig != "" {
		return v.Config.CustomConfig
	}

	var pluginsConfig strings.Builder
	pluginsConfig.WriteString("plugins {\n")
	pluginsConfig.WriteString("  plugin default { enable }\n")
	for _, plugin := range v.Config.EnablePlugins {
		pluginsConfig.WriteString(fmt.Sprintf("  plugin %s { enable }\n", plugin))
	}
	for _, plugin := range v.Config.DisablePlugins {
		pluginsConfig.WriteString(fmt.Sprintf("  plugin %s { disable }\n", plugin))
	}
	pluginsConfig.WriteString("}\n")

	config := fmt.Sprintf(`unix {
	nodaemon
	full-coredump
	cli-listen /var/run/vpp/cli.sock
	pidfile /run/vpp/vpp.pid
}
api-trace { on }
cpu {
	workers %d
}
socksvr {
	socket-name /var/run/vpp/vpp-api-test.sock
}
%s
buffers {
	buffers-per-numa %d
}`, v.Config.WorkersCount, pluginsConfig.String(), v.Config.BuffersPerNuma)

	return config
}

// Start starts the VPP instance in a Docker container
func (v *VppInstance) Start() error {
	v.log.Infof("Starting VPP instance %s", v.Name)

	// Clean up any existing container
	_ = v.Stop()

	// Create socket directory
	if err := os.MkdirAll(v.socketPath, 0755); err != nil {
		return errors.Wrapf(err, "failed to create socket directory %s", v.socketPath)
	}

	// Get repository directory for mounting
	wd, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "failed to get working directory")
	}
	repoDir := filepath.Clean(filepath.Join(wd, "../.."))

	// Build docker run command
	cmdParams := []string{
		"run", "-d", "--privileged",
		"--name", v.ContainerName,
		"-v", fmt.Sprintf("%s:/var/run/vpp/", v.socketPath),
		"-v", "/proc:/proc", // needed for network namespace manipulation
		"-v", "/var/run/netns:/var/run/netns:shared", // needed for pod network namespace access
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
		"-v", fmt.Sprintf("%s:/repo/", repoDir),
		"--pid=host",
		"--env", fmt.Sprintf("LD_LIBRARY_PATH=%s", os.Getenv("LD_LIBRARY_PATH")),
	}

	cmdParams = append(cmdParams, v.ExtraArgs...)
	cmdParams = append(cmdParams, "--entrypoint", v.Binary, v.Image, v.generateVppConfig())

	cmd := exec.Command("docker", cmdParams...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to start VPP container %s", v.ContainerName)
	}

	v.isRunning = true
	v.log.Infof("VPP container %s started successfully", v.ContainerName)

	// Wait a moment for VPP to create socket files and fix permissions
	time.Sleep(500 * time.Millisecond)
	if err := v.fixSocketPermissions(); err != nil {
		v.log.Warnf("Failed to fix socket permissions: %v", err)
	}

	return nil
}

// fixSocketPermissions changes socket file permissions to be accessible by the test process
func (v *VppInstance) fixSocketPermissions() error {
	// Wait for socket file to be created
	maxRetries := 30
	var socketExists bool
	for i := 0; i < maxRetries; i++ {
		cmd := exec.Command("docker", "exec", v.ContainerName, "test", "-e", "/var/run/vpp/vpp-api-test.sock")
		if err := cmd.Run(); err == nil {
			socketExists = true
			break
		}
		if i < maxRetries-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if !socketExists {
		v.log.Warnf("Socket file not found after waiting, attempting chmod anyway")
	}

	// Change permissions on the socket directory and files to allow access
	cmd := exec.Command("docker", "exec", v.ContainerName, "chmod", "-R", "777", "/var/run/vpp/")
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "failed to change socket permissions")
	}

	v.log.Debugf("Fixed socket permissions for VPP instance %s", v.Name)
	return nil
}

// Stop stops and removes the VPP Docker container
func (v *VppInstance) Stop() error {
	if v.vppLink != nil {
		v.vppLink.Close()
		v.vppLink = nil
	}

	cmd := exec.Command("docker", "rm", "-f", v.ContainerName)
	if err := cmd.Run(); err != nil {
		// Container might not exist, which is fine
		v.log.Debugf("Failed to remove container %s: %v", v.ContainerName, err)
	}

	v.isRunning = false
	v.log.Infof("VPP container %s stopped", v.ContainerName)

	return nil
}

// Connect establishes a connection to the VPP API
func (v *VppInstance) Connect() (*vpplink.VppLink, error) {
	if v.vppLink != nil {
		return v.vppLink, nil
	}

	apiSocket := filepath.Join(v.socketPath, "vpp-api-test.sock")

	vppLink, err := common.CreateVppLinkInRetryLoop(
		apiSocket,
		v.log,
		20*time.Second,
		100*time.Millisecond,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to VPP API at %s", apiSocket)
	}

	v.vppLink = vppLink
	v.log.Infof("Connected to VPP instance %s", v.Name)

	return v.vppLink, nil
}

// GetVppLink returns the VppLink connection (must call Connect first)
func (v *VppInstance) GetVppLink() *vpplink.VppLink {
	return v.vppLink
}

// SetVppLink sets the VppLink connection (for testing purposes)
func (v *VppInstance) SetVppLink(vppLink *vpplink.VppLink) {
	v.vppLink = vppLink
}

// IsRunning returns whether the VPP instance is currently running
func (v *VppInstance) IsRunning() bool {
	return v.isRunning
}

// RunCli executes a VPP CLI command
func (v *VppInstance) RunCli(command string) (string, error) {
	if v.vppLink == nil {
		return "", errors.New("VPP link not connected, call Connect() first")
	}
	return v.vppLink.RunCli(command)
}

// Exec runs a command inside the VPP container
func (v *VppInstance) Exec(args ...string) ([]byte, error) {
	cmdArgs := append([]string{"exec", v.ContainerName}, args...)
	cmd := exec.Command("docker", cmdArgs...)
	return cmd.CombinedOutput()
}

// ConfigureUplink configures a TAP interface as uplink with the specified configuration
func (v *VppInstance) ConfigureUplink(config *UplinkConfig) (uint32, error) {
	if v.vppLink == nil {
		return 0, errors.New("VPP link not connected, call Connect() first")
	}

	if config == nil {
		return 0, errors.New("uplink config cannot be nil")
	}

	v.log.Infof("Configuring uplink interface %s", config.InterfaceName)

	// Create TAP interface
	swIfIndex, err := v.vppLink.CreateTapV2(&types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			HostInterfaceName: config.InterfaceName,
			HardwareAddr:      parseMAC("aa:bb:cc:dd:ee:01"),
		},
		Tag:            fmt.Sprintf("main-%s", config.InterfaceName),
		Flags:          types.TapFlagNone,
		HostMtu:        config.MTU,
		HostMacAddress: parseMAC("aa:bb:cc:dd:ee:02"),
	})
	if err != nil {
		return 0, errors.Wrap(err, "failed to create TAP interface")
	}

	// Set interface up
	if err := v.vppLink.InterfaceAdminUp(swIfIndex); err != nil {
		return 0, errors.Wrap(err, "failed to set interface admin up")
	}

	// Configure IPv4 address
	if config.IPv4Address != "" {
		if err := v.vppLink.AddInterfaceAddress(swIfIndex, parseIPNet(config.IPv4Address)); err != nil {
			return 0, errors.Wrap(err, "failed to add IPv4 address")
		}

		// Configure host side
		if _, err := v.Exec("ip", "address", "add", config.IPv4Gateway, "dev", config.InterfaceName); err != nil {
			return 0, errors.Wrap(err, "failed to configure host IPv4 gateway")
		}
	}

	// Configure IPv6 address
	if config.IPv6Address != "" {
		if err := v.vppLink.AddInterfaceAddress(swIfIndex, parseIPNet(config.IPv6Address)); err != nil {
			return 0, errors.Wrap(err, "failed to add IPv6 address")
		}

		// Configure host side
		if _, err := v.Exec("ip", "address", "add", config.IPv6Gateway, "dev", config.InterfaceName); err != nil {
			return 0, errors.Wrap(err, "failed to configure host IPv6 gateway")
		}
	}

	// Bring up host interface
	if _, err := v.Exec("ip", "link", "set", config.InterfaceName, "up"); err != nil {
		return 0, errors.Wrap(err, "failed to bring up host interface")
	}

	v.log.Infof("Uplink interface %s configured successfully (swIfIndex: %d)", config.InterfaceName, swIfIndex)
	return swIfIndex, nil
}

// WaitForReady waits for VPP to be ready by attempting to connect
func (v *VppInstance) WaitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := v.Connect(); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("timeout waiting for VPP to be ready")
}

// UplinkInterface represents an uplink interface created in VPP
type UplinkInterface struct {
	SwIfIndex     uint32
	InterfaceName string
}

// CreateUplinkAfPacket creates an AF_PACKET interface in VPP on a Linux interface
// This mimics the production uplink creation in vpp-manager/uplink/af_packet.go
func (v *VppInstance) CreateUplinkAfPacket(linuxIfName string) (*UplinkInterface, error) {
	if v.vppLink == nil {
		return nil, errors.New("VPP link not connected, call Connect() first")
	}

	v.log.Infof("Creating AF_PACKET uplink interface on %s", linuxIfName)

	// Bring up the Linux interface first
	if _, err := v.Exec("ip", "link", "set", linuxIfName, "up"); err != nil {
		return nil, errors.Wrapf(err, "failed to bring up Linux interface %s", linuxIfName)
	}

	// Create AF_PACKET interface in VPP
	swIfIndex, err := v.vppLink.CreateAfPacket(&types.AfPacketInterface{
		GenericVppInterface: types.GenericVppInterface{
			HostInterfaceName: linuxIfName,
		},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create AF_PACKET interface on %s", linuxIfName)
	}

	// Set interface up
	if err := v.vppLink.InterfaceAdminUp(swIfIndex); err != nil {
		return nil, errors.Wrapf(err, "failed to set AF_PACKET interface %d up", swIfIndex)
	}

	// Enable IPv6
	if err := v.vppLink.EnableInterfaceIP6(swIfIndex); err != nil {
		v.log.Warnf("Failed to enable IPv6 on uplink: %v", err)
	}

	// Tag the interface
	if err := v.vppLink.SetInterfaceTag(swIfIndex, fmt.Sprintf("uplink-%s", linuxIfName)); err != nil {
		v.log.Warnf("Failed to tag uplink interface: %v", err)
	}

	v.log.Infof("Created AF_PACKET uplink interface %d on %s", swIfIndex, linuxIfName)

	return &UplinkInterface{
		SwIfIndex:     swIfIndex,
		InterfaceName: linuxIfName,
	}, nil
}

// CreateHostTap creates a TAP interface for host connectivity
// This mimics the TAP creation in vpp_runner.go:configureVppUplinkInterface
func (v *VppInstance) CreateHostTap(tapName string) (uint32, error) {
	if v.vppLink == nil {
		return 0, errors.New("VPP link not connected, call Connect() first")
	}

	v.log.Infof("Creating host TAP interface %s", tapName)

	tapSwIfIndex, err := v.vppLink.CreateTapV2(&types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			HostInterfaceName: tapName,
			HardwareAddr:      parseMAC("aa:bb:cc:dd:ee:ff"),
		},
		HostNamespace:  "pid:1", // create in root namespace
		Tag:            fmt.Sprintf("host-%s", tapName),
		Flags:          types.TapFlagNone,
		HostMtu:        1500,
		HostMacAddress: parseMAC("aa:bb:cc:dd:ee:fe"),
	})
	if err != nil {
		return 0, errors.Wrapf(err, "failed to create TAP interface %s", tapName)
	}

	// Set TAP up in VPP
	if err := v.vppLink.InterfaceAdminUp(tapSwIfIndex); err != nil {
		return 0, errors.Wrapf(err, "failed to set TAP interface %d up", tapSwIfIndex)
	}

	// Enable IPv6
	if err := v.vppLink.EnableInterfaceIP6(tapSwIfIndex); err != nil {
		v.log.Warnf("Failed to enable IPv6 on TAP: %v", err)
	}

	// Bring up host side
	if _, err := v.Exec("ip", "link", "set", tapName, "up"); err != nil {
		v.log.Warnf("Failed to bring up host TAP interface: %v", err)
	}

	v.log.Infof("Created host TAP interface %d (%s)", tapSwIfIndex, tapName)
	return tapSwIfIndex, nil
}
