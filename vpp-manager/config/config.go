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

package config

const (
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	VppConfigFile          = "/etc/vpp/startup.conf"
	VppConfigExecFile      = "/etc/vpp/startup.exec"
	VppManagerStatusFile   = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile   = "/var/run/vpp/vppmanagertap0"
	VppApiSocket           = "/var/run/vpp/vpp-api.sock"
	CalicoVppPidFile       = "/var/run/vpp/calico_vpp.pid"
	VppPath                = "/usr/bin/vpp"
	HostIfName             = "vpptap0"
	HostIfTag              = "hosttap"
	VppSigKillTimeout      = 2
)
