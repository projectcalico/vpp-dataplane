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

function 6safe () {
  if [[ $(is_ip6 $1) = true ]]; then
	echo "[$1]"
  else
  	echo "$1"
  fi
}

function parse_variables ()
{
  FIRST_POD_CIDR=""
  for cidr in $(echo $POD_CIDR | sed 's/,/ /g' ) ; do
  	if [[ x$FIRST_POD_CIDR == x ]]; then
  		FIRST_POD_CIDR=$cidr
  	fi
	if [[ $(is_ip6 $cidr) == true ]]; then
		CLUSTER_POD_CIDR6=$cidr
	else
		CLUSTER_POD_CIDR4=$cidr
	fi
  done

  FIRST_SERVICE_CIDR=""
  for cidr in $(echo $SERVICE_CIDR | sed 's/,/ /g' ) ; do
  	if [[ x$FIRST_SERVICE_CIDR == x ]]; then
  		FIRST_SERVICE_CIDR=$cidr
  	fi
  done

  FIRST_NODE_IP=""
  for cidr in $(echo $NODE_IP | sed 's/,/ /g' ) ; do
  	if [[ x$FIRST_NODE_IP == x ]]; then
  		FIRST_NODE_IP=${cidr%%/*}
  	fi
  done

  if [[ x$CLUSTER_POD_CIDR4 != x ]] && [[ x$CLUSTER_POD_CIDR6 != x ]]; then
	IS_DUAL=true
  else
	IS_DUAL=false
  fi
}

function calico_if_linux_setup ()
{
  sudo modprobe vfio-pci
  echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

  sudo ip link set $VPP_DATAPLANE_IF down
  if [ x$RENAME_IF != x ]; then
	  sudo ip link set dev $VPP_DATAPLANE_IF name $RENAME_IF
  fi
  sudo ip link set $VPP_DATAPLANE_IF up
  sudo ip addr flush dev $VPP_DATAPLANE_IF
  for cidr in $(echo $NODE_IP | sed 's/,/ /g' ) ; do
	sudo ip addr add $cidr dev $VPP_DATAPLANE_IF
  done
}

function raw_create_cluster_conf ()
{
	# node ip
	export MAIN_NODE_IP=$MAIN_NODE_IP
	export SAFE6_MAIN_NODE_IP="$(6safe $MAIN_NODE_IP)"
	# node ip
	export FIRST_NODE_IP=$FIRST_NODE_IP
	export SAFE6_FIRST_NODE_IP="$(6safe $FIRST_NODE_IP)"

	if [[ $IS_DUAL == true ]]; then
		export NODE_CIDR_MASK_SIZE4=24
		export NODE_CIDR_MASK_SIZE6=120
		export NODE_CIDR_MASK_SIZE=0
	elif [[ x$CLUSTER_POD_CIDR6 != x ]]; then
		export NODE_CIDR_MASK_SIZE4=0
		export NODE_CIDR_MASK_SIZE6=0
		export NODE_CIDR_MASK_SIZE=120
	else
		export NODE_CIDR_MASK_SIZE4=0
		export NODE_CIDR_MASK_SIZE6=0
		export NODE_CIDR_MASK_SIZE=16
	fi
	# pod cidr
	export POD_CIDR=$POD_CIDR
	export FIRST_POD_CIDR=$FIRST_POD_CIDR
	#
	export SERVICE_CIDR=$SERVICE_CIDR
	export FIRST_SERVICE_CIDR=$FIRST_SERVICE_CIDR
	export NODE_NAME=$NODE_NAME
	export DNS_TYPE=$DNS_TYPE
	export IS_DUAL=$IS_DUAL
	export K8_VERSION=${K8_VERSION:=v1.17.4}
    cat $1 | envsubst | sudo tee /tmp/ClusterConf.yaml > /dev/null
}

function raw_create_master_k8 ()
{
	calico_if_linux_setup
	raw_create_cluster_conf $SCRIPTDIR/kubeadm/ClusterNewConfiguration.template.yaml
	if [ x$VERBOSE = xyes ]; then
		sudo kubeadm init -v 100 --config /tmp/ClusterConf.yaml $@
	else
		sudo kubeadm init --config /tmp/ClusterConf.yaml $@
	fi
    rm -rf $HOME/.kube
	mkdir -p $HOME/.kube
	sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
	sudo chown $(id -u):$(id -g) $HOME/.kube/config
	kubectl config set-context --current --namespace=kube-system
}

function raw_join_master_k8 ()
{
	calico_if_linux_setup
	raw_create_cluster_conf $SCRIPTDIR/kubeadm/ClusterJoinConfiguration.template.yaml
	if [ x$VERBOSE = xyes ]; then
		sudo kubeadm join -v 100 $MAIN_NODE_IP:6443 --config /tmp/ClusterConf.yaml $@
	else
		sudo kubeadm join $MAIN_NODE_IP:6443 --config /tmp/ClusterConf.yaml $@
	fi
}

function provision_cli ()
{
	NODE_NAME=node
	POD_CIDR=10.0.0.0/16
	SERVICE_CIDR=10.96.0.0/16
	DNS_TYPE=CoreDNS
	if [[ $1 = up ]]; then
		ACTION=up
	elif [[ $1 = dn ]]; then
		ACTION=dn
	else
		print_usage_and_exit;
	fi
	shift

	while (( "$#" )) ; do
		eval $1
    	shift
	done
	VPP_DATAPLANE_IF=$IF
	if [[ x$VPP_DATAPLANE_IF = x ]] && [[ x$ACTION = up ]]; then
		print_usage_and_exit
	fi


	if [[ $ACTION = up ]]; then
	  green "Creating cluster"
	  green "master ip    : $MAIN_NODE_IP"
	  green "node ip      : $NODE_IP"
	  green "pod cidr     : $POD_CIDR"
	  green "service cidr : $SERVICE_CIDR"
	else
	  green "Teardown cluster"
	fi

	parse_variables
	if [[ $ACTION = up ]] && [[ x$MAIN_NODE_IP = x ]]; then
		raw_create_master_k8
	elif [[ $ACTION = up ]]; then
		raw_join_master_k8
	elif [[ $ACTION = dn ]]; then
		sudo kubeadm reset -f
		sudo rm -rf /etc/cni/net.d/
	fi

}

function print_usage_and_exit ()
{
	echo "Usage :"
	echo "provision.sh [up|dn] [OPTIONS]"
	echo
	echo "On the first node - provision.sh up IF=eth0 NODE_IP=10.0.0.1/24"
	echo "On the second     - provision.sh up IF=eth0 NODE_IP=10.0.0.2/24 MAIN_NODE_IP=10.0.0.1             - start master node <IP>"
	echo
	echo "To drain          - provision.sh dn"
	echo
	echo "Options are :"
	echo "IF             - linux if name to use"
	echo "NODE_IP        - ip of this node"
	echo "MAIN_NODE_IP   - ip of the master node to join (if any)"
	echo "POD_CIDR       - CIDR for pods (defaults to 10.0.0.0/16)"
	echo "SERVICE_CIDR   - CIDR for services (defaults to 10.96.0.0/16)"
	echo "DNS_TYPE       - CoreDNS or kube-dns"
	echo "VERBOSE        - verbose"
	exit 1
}

provision_cli $@

