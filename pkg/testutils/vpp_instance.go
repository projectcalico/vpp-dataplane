// Copyright (C) 2025 Cisco Systems Inc.
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

package testutils

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
}

// DefaultVppConfig returns a default VPP configuration
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
		ContainerName: fmt.Sprintf("vpp-test-%s", name),
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

// Start starts the VPP instance in a Docker container
func (v *VppInstance) Start() error {
	v.log.Infof("Starting VPP instance %s", v.Name)

	// Clean up any existing container
	_ = v.Stop()

	// Create socket directory
	if err := os.MkdirAll(v.socketPath, 0755); err != nil {
		return errors.Wrapf(err, "failed to create socket directory %s", v.socketPath)
	}

	// Build docker run command
	cmdParams := []string{
		"run", "-d", "--privileged",
		"--name", v.ContainerName,
		"-v", fmt.Sprintf("%s:/var/run/vpp/", v.socketPath),
		"-v", "/proc:/proc",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
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

// Stop stops and removes the VPP Docker container
func (v *VppInstance) Stop() error {
	if v.vppLink != nil {
		v.vppLink.Close()
		v.vppLink = nil
	}

	cmd := exec.Command("docker", "rm", "-f", "-v", v.ContainerName)
	if err := cmd.Run(); err != nil {
		// Container might not exist, which is fine
		v.log.Debugf("Failed to remove container %s: %v", v.ContainerName, err)
	}

	// Clean up socket directory
	os.RemoveAll(v.socketPath)

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
