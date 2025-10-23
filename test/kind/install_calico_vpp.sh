#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml

while [[ "$(kubectl api-resources --api-group=operator.tigera.io | grep Installation)" == "" ]]; do echo "waiting for Installation kubectl resource"; sleep 2; done

export TAG=${TAG:-latest}

export CALICO_AGENT_IMAGE=localhost:5000/calicovpp/agent:${TAG}
export MULTINET_MONITOR_IMAGE=localhost:5000/calicovpp/multinet-monitor:${TAG}
if [[ "${DEBUG}" = "true" ]]; then
	export CALICO_VPP_IMAGE=localhost:5000/calicovpp/vpp:dbg-${TAG}
else
	export CALICO_VPP_IMAGE=localhost:5000/calicovpp/vpp:${TAG}
fi

export IMAGE_PULL_POLICY=Always # Always Never IfNotPresent
export CALICOVPP_ENABLE_MEMIF=true
export CALICOVPP_ENABLE_VCL=true
export CALICOVPP_LOG_LEVEL=debug

# ---------------- interfaces ----------------
export CALICOVPP_MAIN_INTERFACE=eth0
export CALICOVPP_INTERFACES='{
    "defaultPodIfSpec": {
      "rx": 1,
      "tx": 1,
      "rxqsz": 128,
      "txqsz": 128,
      "isl3": true,
      "rxMode": "interrupt"
    },
    "vppHostTapSpec": {
      "rx": 1,
      "tx": 1,
      "rxqsz": 512,
      "txqsz": 512,
      "isl3": false,
      "rxMode": "interrupt"
    },
  "uplinkInterfaces": [
    {
      "interfaceName": "eth0",
      "vppDriver": "af_packet",
      "rxMode": "interrupt"
    }
  ]
}'

export CALICOVPP_FEATURE_GATES='{
	"prometheusEnabled": true,
	"vclEnabled": true,
	"memifEnabled": true
}'
export CALICO_ENCAPSULATION_V4=IPIP # VXLAN IPIP None
export CALICO_ENCAPSULATION_V6=None # VXLAN IPIP None

export CALICO_NAT_OUTGOING=Enabled
export CALICOVPP_DISABLE_HUGEPAGES=true

export CALICOVPP_CONFIG_TEMPLATE="unix {
  nodaemon
  full-coredump
  log /var/run/vpp/vpp.log
  cli-listen /var/run/vpp/cli.sock
  pidfile /run/vpp/vpp.pid
}
cpu {
  workers 0
}
socksvr {
  socket-name /var/run/vpp/vpp-api.sock
}
buffers {
  buffers-per-numa 16384
  page-size 4K
}
plugins {
    plugin default { enable }
    plugin calico_plugin.so { enable }
    plugin dpdk_plugin.so { disable }
}
"

${SCRIPTDIR}/../../yaml/overlays/dev/kustomize.sh up
