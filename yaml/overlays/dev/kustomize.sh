#!/bin/bash

# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function is_ip6 () {
  if [[ $1 =~ .*:.*/.* ]]; then
	echo "true"
  else
	echo "false"
  fi
}

function green ()
{
  printf "\e[0;32m$1\e[0m\n"
}

function red ()
{
  printf "\e[0;31m$1\e[0m\n"
}

function get_cluster_service_cidr ()
{
  kubectl cluster-info dump | grep -m 1 service-cluster-ip-range | cut -d '=' -f 2 | cut -d '"' -f 1
}

function get_available_node_names ()
{
  kubectl get nodes -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}'
}

function get_node_addresses ()
{
  kubectl get nodes $1 -o go-template --template='{{range .spec.podCIDRs}}{{printf "%s\n" .}}{{end}}'
}

function kustomize_parse_variables ()
{
  # This sets the following vars unless provided
  # CLUSTER_POD_CIDR4
  # CLUSTER_POD_CIDR6
  # SERVICE_CIDR
  # IP_VERSION

  if [ x${CLUSTER_POD_CIDR4}${CLUSTER_POD_CIDR6} = x ]; then
	FIRST_NODE=$(get_available_node_names | head -1)
	for ip in $(get_node_addresses $FIRST_NODE) ; do
	  if [[ $(is_ip6 $ip) == true ]]; then
		  CLUSTER_POD_CIDR6=$ip
	  else
		  CLUSTER_POD_CIDR4=$ip
	  fi
	done
  fi

  if [ x${IP_VERSION} = x ]; then
	IP_VERSION=""
	if [[ x$CLUSTER_POD_CIDR4 != x ]]; then
  	 IP_VERSION=4
	fi
	if [[ x$CLUSTER_POD_CIDR6 != x ]]; then
  	 IP_VERSION=${IP_VERSION}6
	fi
  fi

  if [ x${SERVICE_CIDR} = x ]; then
	SERVICE_CIDR=$(get_cluster_service_cidr)
  fi
}

function get_vpp_conf ()
{
	echo "
	  unix {
		nodaemon
		full-coredump
		log /var/run/vpp/vpp.log
		cli-listen /var/run/vpp/cli.sock
    	pidfile /run/vpp/vpp.pid
	  }
    api-trace { on }
	  cpu { main-core ${MAINCORE} workers ${WRK} }
	  socksvr {
    	  socket-name /var/run/vpp/vpp-api.sock
	  }
	  buffers {
		buffers-per-numa 65536
	  }
	  plugins {
    	  plugin default { enable }
    	  plugin calico_plugin.so { enable }
    	  plugin dpdk_plugin.so { disable }
        plugin ping_plugin.so { disable }
	  }
	"
}

function get_initial_config ()
{
    echo "
    {
      \"vppStartupSleepSeconds\": ${CALICOVPP_VPP_STARTUP_SLEEP:=0},
      \"corePattern\": \"${CALICOVPP_CORE_PATTERN}\",
      \"defaultGWs\": \"${CALICOVPP_DEFAULT_GW}\"
    }
    "
}

function get_feature_gates ()
{
    echo "
    {
      \"memifEnabled\": ${CALICOVPP_ENABLE_MEMIF},
      \"vclEnabled\": ${CALICOVPP_ENABLE_VCL},
      \"multinetEnabled\": ${CALICOVPP_ENABLE_MULTINET},
      \"ipsecEnabled\": ${CALICOVPP_IPSEC_ENABLED}
    }
    "
}

function get_debug ()
{
    echo "
    {
      \"policiesEnabled\": ${CALICOVPP_DEBUG_ENABLE_POLICIES},
      \"servicesEnabled\": ${CALICOVPP_DEBUG_ENABLE_SERVICES},
      \"maglevEnabled\": ${CALICOVPP_DEBUG_ENABLE_MAGLEV},
      \"gsoEnabled\": ${CALICOVPP_DEBUG_ENABLE_GSO}
    }
    "
}

function get_interfaces ()
{
    echo "
    {
        \"defaultPodIfSpec\": {
          \"rx\": ${CALICOVPP_RX_QUEUES:=1},
          \"tx\": ${CALICOVPP_TX_QUEUES:=1},
          \"isl3\": true,
          \"rxMode\": \"${CALICOVPP_RX_MODE:=adaptive}\"
        },
        \"vppHostTapSpec\": {
          \"rx\": ${CALICOVPP_TAP_RX_QUEUES:=1},
          \"tx\": ${CALICOVPP_TAP_TX_QUEUES:=1},
          \"rxqsz\": 1024, 
          \"txqsz\": 1024, 
          \"isl3\": false,
          \"rxMode\": \"${CALICOVPP_TAP_RX_MODE:=adaptive}\"
        },
        \"uplinkInterfaces\": [
          {
            \"interfaceName\": \"${CALICOVPP_INTERFACE:=eth0}\",
            \"vppDriver\": \"${CALICOVPP_NATIVE_DRIVER:=af_packet}\",
            \"rxMode\": \"${CALICOVPP_RX_MODE:=adaptive}\"
          }
        ]
    }"
}

function get_installation_cidrs ()
{
	if [[ $IP_VERSION == 4 ]]; then
	  echo "
    - cidr: ${CLUSTER_POD_CIDR4}
      encapsulation: ${CALICO_ENCAPSULATION_V4}
      natOutgoing: ${CALICO_NAT_OUTGOING}"
	elif [[ $IP_VERSION == 6 ]]; then
	  echo "
    - cidr: ${CLUSTER_POD_CIDR6}
      encapsulation: ${CALICO_ENCAPSULATION_V6}
      natOutgoing: ${CALICO_NAT_OUTGOING}"
	else
	  echo "
    - cidr: ${CLUSTER_POD_CIDR4}
      encapsulation: ${CALICO_ENCAPSULATION_V4}
      natOutgoing: ${CALICO_NAT_OUTGOING}
    - cidr: ${CLUSTER_POD_CIDR6}
      encapsulation: ${CALICO_ENCAPSULATION_V6}
      natOutgoing: ${CALICO_NAT_OUTGOING}"
	fi
}

function is_v4_v46_v6 ()
{
	if [[ x$IP_VERSION == x4 ]]; then
		echo $1
	elif [[ x$IP_VERSION == x46 ]]; then
		echo $2
	else
		echo $3
  	fi
}

calico_create_template ()
{
  kustomize_parse_variables
  >&2 green "Installing CNI for"
  >&2 green "pod cidr     : ${CLUSTER_POD_CIDR4},${CLUSTER_POD_CIDR6}"
  >&2 green "service cidr : $SERVICE_CIDR"
  >&2 green "is ip6       : $(is_v4_v46_v6 v4 v46 v6)"
  if [ x${CLUSTER_POD_CIDR4}${CLUSTER_POD_CIDR6} = x ]; then
  	>&2 red "No CLUSTER_POD_CIDR[46] set, exiting"
  	exit 1
  fi
  if [ x${IP_VERSION} = x ]; then
  	>&2 red "No IP_VERSION set, exiting"
  	exit 1
  fi
  if [[ x$SERVICE_CIDR = x ]]; then
  	>&2 red "No SERVICE_CIDR set, exiting"
  	exit 1
  fi

  WRK=${WRK:=0}
  MAINCORE=${MAINCORE:=12}
  DPDK=${DPDK:=true}

  export CALICO_AGENT_IMAGE=${CALICO_AGENT_IMAGE:=docker.io/calicovpp/agent:latest}
  export CALICO_VPP_IMAGE=${CALICO_VPP_IMAGE:=docker.io/calicovpp/vpp:latest}
  export MULTINET_MONITOR_IMAGE=${MULTINET_MONITOR_IMAGE:=docker.io/calicovpp/multinet-monitor:latest}
  export CALICO_VERSION_TAG=${CALICO_VERSION_TAG:=v3.20.0}
  export CALICO_CNI_IMAGE=${CALICO_CNI_IMAGE:=docker.io/calico/cni:${CALICO_VERSION_TAG}}
  export IMAGE_PULL_POLICY=${IMAGE_PULL_POLICY:=IfNotPresent}

  export USERHOME=${HOME}
  export REPO_DIRECTORY=$(readlink -f ${SCRIPTDIR}/../../..)

  ## Installation ##

  export CALICO_MTU=${CALICO_MTU:=0}
  export CALICO_ENCAPSULATION_V4=${CALICO_ENCAPSULATION_V4:=IPIP}
  export CALICO_ENCAPSULATION_V6=${CALICO_ENCAPSULATION_V6:=None}
  export CALICO_NAT_OUTGOING=${CALICO_NAT_OUTGOING:=Enabled}
  export CLUSTER_POD_CIDR4=${CLUSTER_POD_CIDR4}
  export INSTALLATION_CIDRS=$(get_installation_cidrs)

  # export CALICO_IPV4POOL_CIDR=$CLUSTER_POD_CIDR4
  # export CALICO_IPV6POOL_CIDR=$CLUSTER_POD_CIDR6
  # export FELIX_IPV6SUPPORT=$(is_v4_v46_v6 false true true)
  # export IP=$(is_v4_v46_v6 autodetect autodetect none)
  # export IP6=$(is_v4_v46_v6 none autodetect autodetect)
  # export cni_network_config=$(get_cni_network_config)
  # export FELIX_XDPENABLED=${FELIX_XDPENABLED:=false}


  ## calico-vpp-config variables ##
  export SERVICE_PREFIX=$SERVICE_CIDR
  export CALICOVPP_INTERFACE=${CALICOVPP_INTERFACE:=eth0}
  export CALICOVPP_NATIVE_DRIVER=${CALICOVPP_NATIVE_DRIVER}
  export CALICOVPP_CONFIG_TEMPLATE=${CALICOVPP_CONFIG_TEMPLATE:=$(get_vpp_conf)}

  ## vpp-dev-config variables (extra variables for VPP-manager) ##
  export CALICOVPP_CORE_PATTERN=${CALICOVPP_CORE_PATTERN:=/home/hostuser/vppcore.%e.%p}
  export CALICOVPP_RX_MODE=${CALICOVPP_RX_MODE:=adaptive}
  export CALICOVPP_RX_QUEUES=${CALICOVPP_RX_QUEUES}
  export CALICOVPP_VPP_STARTUP_SLEEP=${CALICOVPP_VPP_STARTUP_SLEEP:=0}
  export CALICOVPP_CONFIG_EXEC_TEMPLATE=${CALICOVPP_CONFIG_EXEC_TEMPLATE}
  export CALICOVPP_INIT_SCRIPT_TEMPLATE=${CALICOVPP_INIT_SCRIPT_TEMPLATE}
  export CALICOVPP_DEFAULT_GW=${CALICOVPP_DEFAULT_GW}
  export CALICOVPP_DEBUG_ENABLE_GSO=${CALICOVPP_DEBUG_ENABLE_GSO:=true}
  export CALICOVPP_TAP_MTU=${CALICOVPP_TAP_MTU:=0}
  export DEBUG=${DEBUG}

  ## calico-agent-config variables (extra variables for Calico-vpp-agent) ##
  export CALICOVPP_TAP_RX_QUEUES=${CALICOVPP_TAP_RX_QUEUES:=1}
  export CALICOVPP_TAP_TX_QUEUES=${CALICOVPP_TAP_TX_QUEUES:=1}
  export CALICOVPP_IPSEC_ENABLED=${CALICOVPP_IPSEC_ENABLED:=false}
  export CALICOVPP_DEBUG_ENABLE_POLICIES=${CALICOVPP_DEBUG_ENABLE_POLICIES:=true}
  export CALICOVPP_DEBUG_ENABLE_SERVICES=${CALICOVPP_DEBUG_ENABLE_SERVICES:=true}
  export CALICOVPP_DEBUG_ENABLE_MAGLEV=${CALICOVPP_DEBUG_ENABLE_MAGLEV:=true}
  export CALICOVPP_ENABLE_MULTINET=${CALICOVPP_ENABLE_MULTINET:=false}
  export CALICOVPP_ENABLE_MEMIF=${CALICOVPP_ENABLE_MEMIF:=true}
  export CALICOVPP_ENABLE_VCL=${CALICOVPP_ENABLE_VCL:=true}
  export CALICOVPP_IPSEC_IKEV2_PSK=${CALICOVPP_IPSEC_IKEV2_PSK:=keykeykey}

  export CALICOVPP_INITIAL_CONFIG=${CALICOVPP_INITIAL_CONFIG:=$(get_initial_config)}
  export CALICOVPP_INTERFACES=${CALICOVPP_INTERFACES:=$(get_interfaces)}
  export CALICOVPP_DEBUG=${CALICOVPP_DEBUG:=$(get_debug)}

  if [ x$CALICOVPP_ENABLE_MULTINET = xtrue ]; then export USE_MULTINET_MONITOR_DEV_PATCH=true ; fi

  cd $SCRIPTDIR

cat > kustomization.yaml <<EOF
bases:
  - ../../base
  - installation-dev.yaml

${USE_MULTINET_MONITOR_DEV_PATCH:+components:}
${USE_MULTINET_MONITOR_DEV_PATCH:+  - ../../components/multinet}

configMapGenerator:
# extra dev config for the VPP-agent
  - name: calico-agent-dev-config
    namespace: calico-vpp-dataplane
    env: props/calico-agent-dev-config.properties
# extra dev config for VPP
  - name: vpp-dev-config
    namespace: calico-vpp-dataplane
    env: props/vpp-dev-config.properties
# Override base/calico-vpp-daemonset.yaml config variables
  - name: calico-vpp-config
    namespace: calico-vpp-dataplane
    env: props/calico-vpp-config.properties
    behavior: merge
generatorOptions:
  disableNameSuffixHash: true

patchesStrategicMerge:
  - calico-vpp-daemonset-dev-patch.yaml
${USE_MULTINET_MONITOR_DEV_PATCH:+  - multinet-monitor-dev-patch.yaml}
EOF

  kubectl kustomize . | \
	envsubst | \
	sed "s/^  name: vpp-dev-config/  name: vpp-dev-config\n  namespace: calico-vpp-dataplane/g" | \
	sed "s/^  name: calico-agent-dev-config/  name: calico-agent-dev-config\n  namespace: calico-vpp-dataplane/g" | \
	sed "s/^  name: calico-vpp-config/  name: calico-vpp-config\n  namespace: calico-vpp-dataplane/g" | \
	tee /tmp/calico-vpp.yaml > /dev/null

  rm kustomization.yaml
}

function calico_up_cni ()
{
  calico_create_template
  if [ x$DISABLE_KUBE_PROXY = xyes ]; then
    kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
  fi
  if [ -t 1 ]; then
	kubectl apply -f /tmp/calico-vpp.yaml
  else
  	cat /tmp/calico-vpp.yaml
  fi
}

function calico_down_cni ()
{
  calico_create_template
  if [ x$DISABLE_KUBE_PROXY = xy ]; then
    kubectl patch ds -n kube-system kube-proxy --type merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": null}}}}}'
  fi
  kubectl delete -f /tmp/calico-vpp.yaml
}

function print_usage_and_exit ()
{
    echo "Usage:"
    echo "kustomize.sh up     - Install calico dev cni"
    echo "kustomize.sh dn     - Delete calico dev cni"
    echo
    exit 0
}

kustomize_cli ()
{
  if [[ "$1" = "up" ]]; then
	shift
	calico_up_cni $@
  elif [[ "$1" = "dn" ]]; then
	shift
	calico_down_cni $@
  else
  	print_usage_and_exit
  fi
}

kustomize_cli $@
