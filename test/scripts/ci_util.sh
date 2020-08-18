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
source $SCRIPTDIR/shared.sh

CI_CONFIG_FILE=~/.config/calicovppci.sh
PCI_BIND_NIC_TO_KERNEL=~/vpp-manager/vpp_build/extras/scripts/pci-nic-bind-to-kernel

function load_parameters () {
	if [ -f $CI_CONFIG_FILE ]; then
		source $CI_CONFIG_FILE
	else
		echo "Please create $CI_CONFIG_FILE"
		echo "with:"
		echo "IF=eth0"
		echo "NODESSH=hostname"
		exit 1
	fi
	if [[ $(systemctl is-active --quiet kubelet || echo "dead") != dead ]]; then
		red "Kubelet seems to be already started"
		exit 1
	fi
}

# ------------ CLUSTER ------------

function wait_for_cluster () {
	TMP=$(kubectl cluster-info dump | grep -m 1 service-cluster-ip-range)
	while [[ x$TMP == x ]]; do
	  TMP=$(kubectl cluster-info dump | grep -m 1 service-cluster-ip-range)
	  echo "cluster not yet ready..."
	  sleep 5
	done
	TMP=$(kubectl get nodes node1 -o go-template --template='{{range .spec.podCIDRs}}{{printf "%s\n" .}}{{end}}')
	while [[ x$TMP == x ]]; do
	  TMP=$(kubectl get nodes node1 -o go-template --template='{{range .spec.podCIDRs}}{{printf "%s\n" .}}{{end}}')
	  echo "cluster not yet ready..."
	  sleep 5
	done
}

function cluster_provisionning () {
  ACTION=$1
  IF=${IF:=eth0}
  if [[ $V = 6 ]]; then
    POD_CIDR=fd20::0/112
    SERVICE_CIDR=fd10::0/120
    MAIN=fd11::1/124
    OTHERS=fd11::2/124@${NODESSH}
  elif [[ $V = 46 ]]; then
    POD_CIDR=10.0.0.0/16,fd20::0/112
    SERVICE_CIDR=10.96.0.0/16,fd10::0/120
    MAIN=20.0.0.1/24,fd11::1/124
    OTHERS=20.0.0.2/24,fd11::2/124@${NODESSH}
  else
    POD_CIDR=10.0.0.0/16
    SERVICE_CIDR=10.96.0.0/16
    MAIN=20.0.0.1/24
    OTHERS=20.0.0.2/24@${NODESSH}
  fi
  if [[ $N = 1 ]]; then
  	OLD_OTHERS=$OTHERS
    OTHERS=
  fi

  $ORCH $ACTION \
    IF=$IF \
    POD_CIDR=$POD_CIDR \
    SERVICE_CIDR=$SERVICE_CIDR \
    MAIN=$MAIN \
    OTHERS=$OTHERS > $ORCHUP_LOG 2>&1
}

function create_cluster () {
  blue "Starting cluster... at $(date)"
  mkdir -p $LOG_DIR
  cluster_provisionning up
  wait_for_cluster
}

function teardown_cluster () {
  blue "Stopping cluster... at $(date)"
  cluster_provisionning dn
}

# ------------ CNI ------------

function wait_for_calico_vpp () {
	NVPPS=0
	N=${N:=2}
	while [ x$NVPPS != x$N ]; do
	  NVPPS=$(kubectl -n kube-system get pods | grep calico-vpp | grep '2/2' | wc -l)
	  grey "calico not yet ready"
	  sleep 5
	done
}

function start_calico () {
  blue "Starting calico $1... at $(date)"
  export CALICO_NODE_IMAGE=calicovpp/node:latest
  export CALICO_VPP_IMAGE=calicovpp/vpp:latest
  export IMAGE_PULL_POLICY=Never
  export CALICOVPP_CORE_PATTERN=/home/hostuser/vppcore.%e.%p
  export CALICOVPP_TAP_GSO_ENABLED=true
  export CALICOVPP_INTERFACE=$IF

  export CALICOVPP_IPSEC_ENABLED=false

  $KUST up > $CALICOUP_LOG 2>&1
  wait_for_calico_vpp
}

function start_calico_ipsec () {
  export CALICO_IPV4POOL_IPIP=Always
  export CALICO_IPV6POOL_IPIP=Always
  export CALICOVPP_IPSEC_ENABLED=true
  export CALICOVPP_IPSEC_CROSS_TUNNELS=false
  export CALICOVPP_CONFIGURE_EXTRA_ADDRESSES=0
  start_calico
}

function start_calico_ipip () {
  export CALICO_IPV4POOL_IPIP=Always
  export CALICO_IPV6POOL_IPIP=Always
  start_calico
}

# ------------ Test framework ------------

function wait_for_coredns () {
	NVPPS=0
	while [ x$NVPPS != x2 ]; do
	  NVPPS=$(kubectl -n kube-system get pods | grep coredns | grep '1/1' | wc -l)
	  echo "coredns not yet ready..."
	  sleep 5
	done
}

function wait_for_calico_test () {
	NPODS=0
	N=${N:=2}
	sleep 1
	while [ x$NPODS != x1 ]; do
	  if [[ $N == 1 ]]; then
		NPODS=$(kubectl -n $SVC get pods | grep -v node2 | grep -v Running | wc -l)
	  else
		NPODS=$(kubectl -n $SVC get pods | grep -v Running | wc -l)
	  fi
	  echo "test not yet ready..."
	  sleep 1
	done
}

function start_test () {
	echo "Starting test clients... at $(date)"
	$SCRIPTDIR/test.sh up iperf > iperfup.log 2>&1
	wait_for_coredns
	SVC=iperf wait_for_calico_test
}

function start_iperf4 () {
	ssh $NODESSH -t "$PCI_BIND_NIC_TO_KERNEL"
	ssh $NODESSH -t "sudo ip link set $IF up" > /dev/null 2>&1
	ssh $NODESSH -t "sudo ip addr add 20.0.0.2/24 dev $IF" > /dev/null 2>&1 || true
	ssh $NODESSH -t "nohup bash -c 'iperf -s -B 20.0.0.2 > /tmp/iperf.log 2>&1 &'" > /dev/null 2>&1
}

function start_iperf6 () {
	ssh $NODESSH -t "$PCI_BIND_NIC_TO_KERNEL"
	ssh $NODESSH -t "sudo ip link set $IF up" > /dev/null 2>&1
	ssh $NODESSH -t "sudo ip addr add fd11::2/120 dev $IF" > /dev/null 2>&1 || true
	ssh $NODESSH -t "nohup bash -c 'iperf -s -V -B fd11::2 > /tmp/iperf.log 2>&1 &'" > /dev/null 2>&1
}

function stop_iperf () {
	ssh $NODESSH -t "sudo pkill iperf ; cat /tmp/iperf.log" > $LAST_TEST_LOGFILE 2> /dev/null
}

function sshtest () {
	echo "-----------TESTCASE $1-----------" > $LAST_TEST_LOGFILE
	ssh $NODESSH -t "timeout -k 1 4 ${@:2}" >> $LAST_TEST_LOGFILE
	CODE=$?
	if [ x$CODE = x0 ]; then
	  green "$1 .... OK"
	else
	  red "$1 .... FAILED exit=$CODE"
	fi
	cat $LAST_TEST_LOGFILE >> $LOGFILE
}
