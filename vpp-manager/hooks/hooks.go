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

package hooks

import (
	_ "embed"

	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpp-manager/utils"
	log "github.com/sirupsen/logrus"
)

const (
	/* Run this before getLinuxConfig() in case this is a script
	 * that's responsible for creating the interface */
	BEFORE_IF_READ = "BEFORE_IF_READ" // InitScriptTemplate
	/* Bash script template run just after getting config
	   from $CALICOVPP_INTERFACE & before starting VPP */
	BEFORE_VPP_RUN = "BEFORE_VPP_RUN" // InitPostIfScriptTemplate
	/* Bash script template run after VPP has started */
	VPP_RUNNING = "VPP_RUNNING" // FinalizeScriptTemplate
	/* Bash script template run when VPP stops gracefully */
	VPP_DONE_OK = "VPP_DONE_OK"
	/* Bash script template run when VPP stops with an error */
	VPP_ERRORED = "VPP_ERRORED"
)

var (
	AllHooks        = []string{BEFORE_IF_READ, BEFORE_VPP_RUN, VPP_RUNNING, VPP_DONE_OK, VPP_ERRORED}
	vppManagerHooks = make(map[string][]func(params *config.VppManagerParams, conf []*config.LinuxInterfaceState) error)

	//go:embed network_restart.sh
	DEFAULT_RESTART_SCRIPT string
)

func RegisterBashHook(name string, bashTemplate string) {
	RegisterHook(name, func(params *config.VppManagerParams, conf []*config.LinuxInterfaceState) error {
		return utils.RunBashScript(config.TemplateScriptReplace(bashTemplate, params, nil))
	})
}

func RegisterHook(name string, hook func(params *config.VppManagerParams, conf []*config.LinuxInterfaceState) error) {
	vppManagerHooks[name] = append(vppManagerHooks[name], hook)
}

func HookCount(name string) int {
	return len(vppManagerHooks[name])
}

func RunHook(name string, params *config.VppManagerParams, conf []*config.LinuxInterfaceState) {
	if _, ok := vppManagerHooks[name]; !ok {
		return
	}
	for i, hook := range vppManagerHooks[name] {
		err := hook(params, conf)
		if err != nil {
			log.Warnf("Running hook %s [%d] errored with %s", name, i, err)
		}
	}
}
