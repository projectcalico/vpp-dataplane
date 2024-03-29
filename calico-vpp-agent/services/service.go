// Copyright (C) 2023 Cisco Systems Inc.
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

package services

import "github.com/projectcalico/vpp-dataplane/v3/vpplink/types"

type lbType string

const (
	lbTypeECMP      lbType = "ECMP"
	lbTypeMaglev    lbType = "Maglev"
	lbTypeMaglevDSR lbType = "MaglevDSR"
)

type serviceInfo struct {
	keepOriginalPacket bool
	lbType             lbType
	hashConfig         types.IPFlowHash
}
