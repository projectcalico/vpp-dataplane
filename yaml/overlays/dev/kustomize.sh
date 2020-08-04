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

function get_cluster_service_cidr ()
{
  kubectl cluster-info dump | grep -m 1 service-cluster-ip-range | cut -d '=' -f 2 | cut -d '"' -f 1
}

function get_cluster_pod_cidr ()
{
  kubectl cluster-info dump | grep -m 1 cluster-cidr | cut -d '=' -f 2 | cut -d '"' -f 1
}

function get_vpp_conf ()
{
	echo "
	  unix {
		nodaemon
		full-coredump
		log /var/run/vpp/vpp.log
		cli-listen /var/run/vpp/cli.sock
	  }
	  cpu { main-core 12 workers ${WRK} }
	  socksvr {
    	  socket-name /var/run/vpp/vpp-api.sock
	  }
	  session {
    	  evt_qs_memfd_seg
	  }
	  dpdk {
		dev __PCI_DEVICE_ID__ { num-rx-queues ${RXQ} }
	  }
	  buffers {
		buffers-per-numa 65536
	  }
	  plugins {
    	  plugin default { enable }
    	  plugin calico_plugin.so { enable }
	  }
	"
}

function get_cni_network_config ()
{
	echo '{
      "name": "k8s-pod-network",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "calico",
          "log_level": "debug",
          "datastore_type": "kubernetes",
          "nodename": "__KUBERNETES_NODE_NAME__",
          "mtu": __CNI_MTU__,
          "ipam": {
              "type": "calico-ipam",
              "assign_ipv4": "${IP4}",
              "assign_ipv6": "${IP6}"
          },
          "policy": {
              "type": "k8s"
          },
          "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
          },
          "dataplane_options": {
            "type": "grpc",
            "socket": "unix:///var/run/calico/cni-server.sock"
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }'
}

calico_create_template ()
{
  RXQ=${RXQ:=4}
  WRK=${WRK:=0}
  DPDK=${DPDK:=true}
  IP4=${IP4:=true}
  IP6=${IP6:=false}
  export POD_CIDR=$(get_cluster_pod_cidr)
  export SERVICE_PREFIX=$(get_cluster_service_cidr)
  export cni_network_config=$(get_cni_network_config)
  export CALICOVPP_CONFIG_TEMPLATE=${CALICOVPP_CONFIG_TEMPLATE:=$(get_vpp_conf)}
  export CALICOVPP_CONFIG_EXEC_TEMPLATE=${VPP_CONFIG_EXEC_TEMPLATE:=#}
  export CALICOVPP_INIT_SCRIPT_TEMPLATE=${VPP_INIT_SCRIPT_TEMPLATE:=#}
  export CALICO_NODE_IMAGE=${CALICO_NODE_IMAGE:=calicovpp/vpp:latest}
  export CALICO_VPP_IMAGE=${CALICO_VPP_IMAGE:=calicovpp/vpp:latest}
  export CALICO_VERSION_TAG=${CALICO_VERSION_TAG:=v3.15.1}
  export CALICO_CNI_IMAGE=${CALICO_CNI_IMAGE:=calico/cni:${CALICO_VERSION_TAG}}
  export IMAGE_PULL_POLICY=${IMAGE_PULL_POLICY:=IfNotPresent}
  export CALICOVPP_VPP_STARTUP_SLEEP=${CALICOVPP_VPP_STARTUP_SLEEP:=0}
  export CALICOVPP_TAP_RX_QUEUES=${CALICOVPP_TAP_RX_QUEUES:=1}
  export CALICOVPP_TAP_GSO_ENABLED=${CALICOVPP_TAP_GSO_ENABLED:=false}
  export CALICOVPP_IPSEC_ENABLED=${CALICOVPP_IPSEC_ENABLED:=false}
  export CALICOVPP_NAT_ENABLED=${CALICOVPP_NAT_ENABLED:=true}
  export CALICOVPP_IPSEC_IKEV2_PSK=${CALICOVPP_IPSEC_IKEV2_PSK:=keykeykey}
  export CALICO_IPV4POOL_IPIP=${CALICO_IPV4POOL_IPIP:=Never}
  export CALICOVPP_INTERFACE=${CALICOVPP_INTERFACE:=eth0}
  export CALICOVPP_CONFIGURE_EXTRA_ADDRESSES=${CALICOVPP_CONFIGURE_EXTRA_ADDRESSES:=0}
  export CALICOVPP_IPSEC_CROSS_TUNNELS=${CALICOVPP_IPSEC_CROSS_TUNNELS:=false}
  export CALICOVPP_CORE_PATTERN=${CALICOVPP_CORE_PATTERN:=}
  export CALICOVPP_RX_MODE=${CALICOVPP_RX_MODE:=adaptive}
  export CALICOVPP_TAP_RX_MODE=${CALICOVPP_TAP_RX_MODE:=adaptive}
  export CALICOVPP_USE_AF_PACKET=${CALICOVPP_USE_AF_PACKET:=false}
  export CALICOVPP_SWAP_DRIVER=${CALICOVPP_SWAP_DRIVER:=}
  export USERHOME=${HOME}
  cd $SCRIPTDIR
  kubectl kustomize . | envsubst > /tmp/calico-vpp.yaml
}

function calico_up_cni ()
{
  echo "Installing CALICO CNI..."
  calico_create_template
  if [ x$DISABLE_KUBE_PROXY = xyes ]; then
    kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
  fi
  kubectl apply -f /tmp/calico-vpp.yaml
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