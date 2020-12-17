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
  if [[ $1 =~ .*:.* ]]; then
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
	  cpu { main-core ${MAINCORE} workers ${WRK} }
	  socksvr {
    	  socket-name /var/run/vpp/vpp-api.sock
	  }
	  session {
    	  evt_qs_memfd_seg
	  }
	  buffers {
		buffers-per-numa 65536
	  }
	  plugins {
    	  plugin default { enable }
    	  plugin calico_plugin.so { enable }
    	  plugin dpdk_plugin.so { disable }
	  }
	"
}

function get_cni_network_config_ipam ()
{
	if [[ $IP_VERSION == 4 ]]; then
	  echo "{
        \"type\": \"calico-ipam\",
		\"assign_ipv4\": \"true\",
    	\"assign_ipv6\": \"false\"
	  }"
	elif [[ $IP_VERSION == 6 ]]; then
	  echo "{
        \"type\": \"calico-ipam\",
		\"assign_ipv4\": \"false\",
    	\"assign_ipv6\": \"true\",
		\"ipv6_pools\": [\"${CALICO_IPV6POOL_CIDR}\", \"default-ipv6-ippool\"]
	  }"
	else
	  echo "{
    	\"type\": \"calico-ipam\",
		\"assign_ipv4\": \"true\",
    	\"assign_ipv6\": \"true\",
		\"ipv4_pools\": [\"${CALICO_IPV4POOL_CIDR}\"],
		\"ipv6_pools\": [\"${CALICO_IPV6POOL_CIDR}\"]
	  }"
	fi
}

function get_cni_network_config ()
{
	echo "{
      \"name\": \"k8s-pod-network\",
      \"cniVersion\": \"0.3.1\",
      \"plugins\": [
        {
          \"type\": \"calico\",
          \"log_level\": \"debug\",
          \"datastore_type\": \"kubernetes\",
          \"nodename\": \"__KUBERNETES_NODE_NAME__\",
          \"mtu\": __CNI_MTU__,
          \"ipam\": $(get_cni_network_config_ipam),
          \"policy\": {
              \"type\": \"k8s\"
          },
          \"kubernetes\": {
              \"kubeconfig\": \"__KUBECONFIG_FILEPATH__\"
          },
          \"dataplane_options\": {
            \"type\": \"grpc\",
            \"socket\": \"unix:///var/run/calico/cni-server.sock\"
          }
        },
        {
          \"type\": \"portmap\",
          \"snat\": true,
          \"capabilities\": {\"portMappings\": true}
        }
      ]
    }"
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
  export default_ipv4_pool_cidr=$CLUSTER_POD_CIDR4
  export CALICO_IPV6POOL_CIDR=$CLUSTER_POD_CIDR6
  export FELIX_IPV6SUPPORT=$(is_v4_v46_v6 false true true)
  export IP=$(is_v4_v46_v6 autodetect autodetect none)
  export IP6=$(is_v4_v46_v6 none autodetect autodetect)

  export service_prefix=$SERVICE_CIDR
  export cni_network_config=$(get_cni_network_config)
  export vpp_uplink_driver=${CALICOVPP_NATIVE_DRIVER}
  export vpp_dataplane_interface=${CALICOVPP_INTERFACE:=eth0}
  export vpp_config_template=${CALICOVPP_CONFIG_TEMPLATE:=$(get_vpp_conf)}
  export veth_mtu=${CALICOVPP_TAP_MTU:=0}

  export CALICOVPP_CONFIG_EXEC_TEMPLATE=${CALICOVPP_CONFIG_EXEC_TEMPLATE}
  export CALICOVPP_INIT_SCRIPT_TEMPLATE=${CALICOVPP_INIT_SCRIPT_TEMPLATE}
  export CALICO_NODE_IMAGE=${CALICO_NODE_IMAGE:=calicovpp/node:latest}
  export CALICO_VPP_IMAGE=${CALICO_VPP_IMAGE:=calicovpp/vpp:latest}
  export CALICO_VERSION_TAG=${CALICO_VERSION_TAG:=v3.17.1}
  export CALICO_CNI_IMAGE=${CALICO_CNI_IMAGE:=calico/cni:${CALICO_VERSION_TAG}}
  export IMAGE_PULL_POLICY=${IMAGE_PULL_POLICY:=IfNotPresent}
  export CALICOVPP_VPP_STARTUP_SLEEP=${CALICOVPP_VPP_STARTUP_SLEEP:=0}
  export CALICOVPP_TAP_RX_QUEUES=${CALICOVPP_TAP_RX_QUEUES:=1}
  export CALICOVPP_TAP_TX_QUEUES=${CALICOVPP_TAP_TX_QUEUES:=1}
  export CALICOVPP_TAP_GSO_ENABLED=${CALICOVPP_TAP_GSO_ENABLED:=true}
  export CALICOVPP_IPSEC_ENABLED=${CALICOVPP_IPSEC_ENABLED:=false}
  export CALICOVPP_NAT_ENABLED=${CALICOVPP_NAT_ENABLED:=true}
  export CALICOVPP_POLICIES_ENABLED=${CALICOVPP_POLICIES_ENABLED:=true}
  export CALICOVPP_IPSEC_IKEV2_PSK=${CALICOVPP_IPSEC_IKEV2_PSK:=keykeykey}
  export CALICO_IPV4POOL_IPIP=${CALICO_IPV4POOL_IPIP:=Never}
  export CALICO_IPV4POOL_VXLAN=${CALICO_IPV4POOL_VXLAN:=Never}
  export CALICOVPP_CONFIGURE_EXTRA_ADDRESSES=${CALICOVPP_CONFIGURE_EXTRA_ADDRESSES:=0}
  export CALICOVPP_IPSEC_CROSS_TUNNELS=${CALICOVPP_IPSEC_CROSS_TUNNELS:=false}
  export CALICOVPP_CORE_PATTERN=${CALICOVPP_CORE_PATTERN:=/home/hostuser/vppcore.%e.%p}
  export CALICOVPP_RX_MODE=${CALICOVPP_RX_MODE:=adaptive}
  export CALICOVPP_TAP_RX_MODE=${CALICOVPP_TAP_RX_MODE:=adaptive}
  export CALICOVPP_SWAP_DRIVER=${CALICOVPP_SWAP_DRIVER:=}
  export CALICO_IPV4POOL_NAT_OUTGOING=${CALICO_IPV4POOL_NAT_OUTGOING:=true}
  export CALICO_IPV6POOL_NAT_OUTGOING=${CALICO_IPV6POOL_NAT_OUTGOING:=true}
  export CALICOVPP_TAP_RING_SIZE=${CALICOVPP_TAP_RING_SIZE}
  export USERHOME=${HOME}
  export FELIX_XDPENABLED=${FELIX_XDPENABLED:=false}
  export IP_AUTODETECTION_METHOD=${IP_AUTODETECTION_METHOD:=interface=$vpp_dataplane_interface}
  export IP6_AUTODETECTION_METHOD=${IP6_AUTODETECTION_METHOD:=interface=$vpp_dataplane_interface}
  cd $SCRIPTDIR
  kubectl kustomize . | envsubst | sudo tee /tmp/calico-vpp.yaml > /dev/null
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