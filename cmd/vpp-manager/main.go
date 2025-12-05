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
	"context"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/pkg/config"
	vppmanager "github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/params"
	"github.com/projectcalico/vpp-dataplane/v3/pkg/vpp-manager/uplink"
)

func main() {
	log := logrus.New()
	err := config.LoadConfig(log)
	if err != nil {
		log.WithError(err).Panic("Error loading configuration")
	}
	params := params.NewVppManagerParams()
	for _, intf := range params.Interfaces {
		intf.Driver = uplink.NewUplinkDriver(intf.Spec.VppDriver, params, intf, log.WithFields(logrus.Fields{
			"subcomponent": "uplinkdriver",
		}))
	}
	runner := vppmanager.NewVPPRunner(params, log.WithFields(logrus.Fields{
		"subcomponent": "vppmgm",
	}))
	err = runner.Run(context.Background(), make(chan bool))
	if err != nil {
		log.Errorf("VPP run failed with %v", err)
	}
}
