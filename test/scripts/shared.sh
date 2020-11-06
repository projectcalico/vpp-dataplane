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

if [[ "$X" != "" ]]; then set -x ; fi

ORCH=$SCRIPTDIR/../baremetal/orch.sh
CASES=$SCRIPTDIR/../scripts/cases.sh
KUST=$SCRIPTDIR/../../yaml/overlays/dev/kustomize.sh

LOG_DIR=/tmp/calicovppci
ORCHUP_LOG=$LOG_DIR/orchup.log
CALICOUP_LOG=$LOG_DIR/calicoup.log
LOGFILE=$LOG_DIR/testrun.log
LAST_TEST_LOGFILE=$LOG_DIR/testrun.log~

CI_CONFIG_FILE=~/.config/calicovppci.sh
PCI_BIND_NIC_TO_KERNEL=$SCRIPTDIR/../baremetal/utils/pci-nic-bind-to-kernel

function green () { printf "\e[0;32m$1\e[0m\n" ; }
function red   () { printf "\e[0;31m$1\e[0m\n" ; }
function blue  () { printf "\e[0;34m$1\e[0m\n" ; }
function grey  () { printf "\e[0;37m$1\e[0m\n" ; }

find_node_pod () # NODE, POD
{
  SVC=${SVC:=kube-system}
  echo $(kubectl get pods -n $SVC --field-selector="spec.nodeName=$NODE" | grep $POD | cut -d ' ' -f 1)
}

exec_node () # C, POD, NODE
{
  SVC=${SVC:=kube-system}
  local pod_name=$(find_node_pod)
  if [ x$pod_name == x ]; then
    >&2 echo "pod '$POD' not found on node '$NODE'"
  	exit 1
  else
	kubectl exec -it -n $SVC $pod_name -c $C -- $@
  fi
}

log_node () # C, POD, NODE
{
  SVC=${SVC:=kube-system}
  local pod_name=$(find_node_pod)
  if [ x$pod_name == x ]; then
    >&2 echo "pod '$POD' not found on node '$NODE'"
  	exit 1
  else
	kubectl logs $FOLLOW -n $SVC $pod_name -c $C
  fi
}

vppdev_run_vppctl () # nodeID args
{
  NODE=$1 POD=calico-vpp-node C=vpp exec_node \
	/usr/bin/vppctl -s /var/run/vpp/cli.sock ${@:2}
}

function 6safe () { if [[ "$USE_IP6" = "yes" ]]; then echo "[$1]" ; else echo "$1" ; fi }
function get_listen_addr () { if [[ "$USE_IP6" = "yes" ]]; then echo "::" ; else echo "0.0.0.0" ; fi }

function check_no_running_kubelet ()
{
	if [[ $(systemctl is-active --quiet kubelet || echo "dead") != dead ]]; then
		red "Kubelet seems to be already started"
		exit 1
	fi
}

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
}
