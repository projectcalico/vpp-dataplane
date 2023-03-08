// Copyright (C) 2021 Cisco Systems Inc.
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

package vpplink

import (
	"fmt"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/vlib"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/vpe"
)

func (v *VppLink) GetVPPVersion() (string, error) {
	client := vpe.NewServiceClient(v.GetConnection())

	response, err := client.ShowVersion(v.GetContext(), &vpe.ShowVersion{})
	if err != nil {
		return "", fmt.Errorf("failed to get VPP version: %w", err)
	}
	return response.Version, nil
}

// RunCli sends CLI command to VPP and returns response.
func (v *VppLink) RunCli(cmd string) (string, error) {
	client := vlib.NewServiceClient(v.GetConnection())

	response, err := client.CliInband(v.GetContext(), &vlib.CliInband{
		Cmd: cmd,
	})
	if err != nil {
		return "", fmt.Errorf("failed to run VPP CLI command %q: %w", cmd, err)
	}
	return response.Reply, nil
}
