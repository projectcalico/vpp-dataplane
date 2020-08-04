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

function 6safe () {
  if [[ $(is_ip6 $1) = true ]]; then
	echo "[$1]"
  else
  	echo "$1"
  fi
}

function get_listen_addr () {
  if [[ $(is_ip6 $1) = true ]]; then
  	echo "::"
  else
  	echo "0.0.0.0"
  fi
}

function calico_if_linux_setup ()
{
  sudo modprobe vfio-pci
  echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

  sudo $SCRIPTDIR/utils/pci-nic-bind-to-kernel
  sudo ip link set $VPP_DATAPLANE_IF down
  sudo ip link set $VPP_DATAPLANE_IF up
  sudo ip addr flush dev $VPP_DATAPLANE_IF
  sudo ip addr add $NODE_IP dev $VPP_DATAPLANE_IF

  if [ x$AVF = xyes ]; then
  	calico_avf_setup $VPP_DATAPLANE_IF 1 $@
  fi
}

function calico_avf_setup ()
{
  DEVNAME=$1
  PCI=$(readlink /sys/class/net/$DEVNAME/device | cut -d '/' -f 4)
  AVF_PCI=nope
  if [ -f /home/nskrzypc/vpp/vfpci$2 ]; then
  	AVF_PCI=$(cat /home/nskrzypc/vpp/vfpci$2)
  fi
  if [ ! -d /sys/bus/pci/devices/$AVF_PCI ]; then
  	if [ x$3 = xmaster ]; then
		sudo $SCRIPTDIR/utils/avf.sh $PCI 00:11:22:33:4$2:00
	else
		sudo $SCRIPTDIR/utils/avf.sh $PCI 00:11:22:33:4$2:01
	fi
	mv -f /home/nskrzypc/vpp/vfpci /home/nskrzypc/vpp/vfpci$2
  fi
}

function raw_create_cluster_conf ()
{
    cat $1 | tee /tmp/ClusterConf.yaml > /dev/null 2>&1
	sed -i "s^__MASTER_NODE_IP__^$MASTER_NODE_IP^g" /tmp/ClusterConf.yaml
	sed -i "s^__6SAFE_MASTER_NODE_IP__^$(6safe $MASTER_NODE_IP)^g" /tmp/ClusterConf.yaml
	sed -i "s^__NODE_IP__^${NODE_IP%%/*}^g" /tmp/ClusterConf.yaml
	sed -i "s^__6SAFE_NODE_IP__^$(6safe ${NODE_IP%%/*})^g" /tmp/ClusterConf.yaml
	sed -i "s^__POD_CIDR__^$POD_CIDR^g" /tmp/ClusterConf.yaml
	sed -i "s^__SERVICE_CIDR__^$SERVICE_CIDR^g" /tmp/ClusterConf.yaml
	sed -i "s^__NODE_NAME__^$NODE_NAME^g" /tmp/ClusterConf.yaml
	sed -i "s^__DNS_TYPE__^$DNS_TYPE^g" /tmp/ClusterConf.yaml
	sed -i "s^__LISTEN_ADDR__^$(get_listen_addr ${NODE_IP%%/*})^g" /tmp/ClusterConf.yaml
}

function raw_create_master_k8 ()
{
	echo "MASTER_NODE_IP : $MASTER_NODE_IP"
	echo "NODE_IP        : $NODE_IP"
	calico_if_linux_setup master
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
	echo "MASTER_NODE_IP : $MASTER_NODE_IP"
	echo "NODE_IP        : $NODE_IP"
	calico_if_linux_setup slave
	raw_create_cluster_conf $SCRIPTDIR/kubeadm/ClusterJoinConfiguration.template.yaml
	if [ x$VERBOSE = xyes ]; then
		sudo kubeadm join -v 100 $MASTER_NODE_IP:6443 --config /tmp/ClusterConf.yaml $@
	else
		sudo kubeadm join $MASTER_NODE_IP:6443 --config /tmp/ClusterConf.yaml $@
	fi
}

function provision_cli ()
{
	NODE_NAME=$(hostname)
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

	if [[ $ACTION = up ]] && [[ x$MASTER_NODE_IP = x ]]; then
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
	echo "On the second     - provision.sh up IF=eth0 NODE_IP=10.0.0.2/24 MASTER_NODE_IP=10.0.0.1             - start master node <IP>"
	echo
	echo "To drain          - provision.sh dn"
	echo
	echo "Options are :"
	echo "IF             - linux if name to use"
	echo "NODE_IP        - ip of this node"
	echo "MASTER_NODE_IP - ip of the master node to join (if any)"
	echo "POD_CIDR       - CIDR for pods (defaults to 10.0.0.0/16)"
	echo "SERVICE_CIDR   - CIDR for services (defaults to 10.96.0.0/16)"
	echo "DNS_TYPE       - CoreDNS or kube-dns"
	echo "AVF            - if 'yes' Create a VF for vpp's avf driver"
	echo "VERBOSE        - verbose"
	exit 1
}

provision_cli $@

