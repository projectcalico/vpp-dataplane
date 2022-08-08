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

	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/vpe"
	"go.fd.io/govpp/binapi/vlib"
	"github.com/pkg/errors"
)

func (v *VppLink) GetVPPVersion() (version string, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vpe.ShowVersionReply{}
	request := &vpe.ShowVersion{}

	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return "", errors.Wrapf(err, "ShowVersion failed: req %+v reply %+v", request, response)
	} else if response.Retval != 0 {
		return "", fmt.Errorf("ShowVersion failed (retval %d). Request: %+v", response.Retval, request)
	}
	return response.Version, nil
}

// RunCli sends CLI command to VPP and returns response.
func (v *VppLink) RunCli(cmd string) (string, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &vlib.CliInbandReply{}
	request := &vlib.CliInband{Cmd: cmd}

	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return "", errors.Wrapf(err, "VPP CLI command '%s' failed", cmd)
	} else if err = api.RetvalToVPPApiError(response.Retval); err != nil {
		return "", err
	}
	return response.Reply, nil
}
