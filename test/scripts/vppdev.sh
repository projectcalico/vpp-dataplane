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

vppdev_run_vppctl () # nodeID args
{
  NODE=$1 POD=calico-vpp-node C=vpp exec_node \
	/usr/bin/vppctl -s /var/run/vpp/cli.sock ${@:2}
}

vppdev_attach_vpp_gdb ()
{
  CONTAINER=$(docker ps | grep vpp_calico-vpp | cut -d ' ' -f 1)
  PID=$(docker logs $CONTAINER 2>&1 | grep "VPP started. PID: " | \
	sed -r 's/.*PID: ([0-9]+).*/\1/')
  docker exec -it $CONTAINER gdb -p $PID -ex continue
}

vppdev_coredns_apiserver_test() {
	COREDNS_N=$1
	COREDNS_TOTAL=$(docker ps | grep "coredns -conf" | cut -d ' ' -f 1 | wc -l)
	echo "Found $COREDNS_TOTAL coredns"
	if [ x$COREDNS_TOTAL = x0 ]; then
		exit 0
	fi
	COREDNS_DOCKERID=$(docker ps | grep "coredns -conf" | cut -d ' ' -f 1 | head -n $COREDNS_N | tail -n 1)
	COREDNS_PID=$(docker inspect --format '{{ .State.Pid }}' $COREDNS_DOCKERID )
	sudo nsenter -t $COREDNS_PID -n curl -k 'https://[fd10::1]:443'
}

vppdev_validate_v46 () {
	green ".spec.podCIDRs"
	kubectl get nodes node1 -o go-template --template='{{range .spec.podCIDRs}}{{printf "%s\n" .}}{{end}}'
	green ".status.addresses"
	kubectl get nodes node1 -o go-template --template='{{range .status.addresses}}{{printf "%s: %s \n" .type .address}}{{end}}'
}

vppdev_cli ()
{
  if [[ "$1" = "up" ]]; then
	if [ -f $SCRIPTDIR/conf/$2 ]; then
		echo "Using conf from $SCRIPTDIR/conf/$2"
		source $SCRIPTDIR/conf/$2
	fi
    calico_up_cni
	elif [[ "$1" = "down" ]]; then
	if [ -f $SCRIPTDIR/conf/$2 ]; then
		echo "Using conf from $SCRIPTDIR/conf/$2"
		source $SCRIPTDIR/conf/$2
	fi
    calico_down_cni
  # ---------------------------------
  #               SHELLS
  # ---------------------------------
  elif [[ "$1" = "vppctl" ]]; then
    vppdev_run_vppctl ${@:2}
  elif [[ "$1" = "gdb" ]]; then
    vppdev_attach_vpp_gdb
  elif [[ "$1" = "validate" ]]; then
  	vppdev_validate_v46
  elif [[ "$1" = "coredns" ]]; then
  	shift
    vppdev_coredns_apiserver_test $@
  elif [[ "$1 $2" = "log vpp" ]]; then
    NODE=$3 POD=calico-vpp-node C=vpp log_node
  elif [[ "$1 $2" = "tail vpp" ]]; then
    NODE=$3 POD=calico-vpp-node C=vpp FOLLOW="-f" log_node
  elif [[ "$1 $2" = "log node" ]]; then
    NODE=$3 POD=calico-vpp-node C=calico-node exec_node \
      cat /var/log/calico/calico-vpp-agent/current
  elif [[ "$1 $2" = "tail node" ]]; then
    NODE=$3 POD=calico-vpp-node C=calico-node exec_node \
      tail -f /var/log/calico/calico-vpp-agent/current
  elif [[ "$1 $2" = "sh vpp" ]]; then
    NODE=$3 POD=calico-vpp-node C=vpp exec_node bash
  elif [[ "$1 $2" = "sh node" ]]; then
    NODE=$3 POD=calico-vpp-node C=calico-node exec_node bash
  else
    echo "Usage:"
    echo "$(basename -- $0) gdb                               - Attach a gdb to the running vpp on the current machine"
    echo "$(basename -- $0) coredns [N]                       - test Nth coredns connectivity to the apiserver"
    echo
    echo "$(basename -- $0) vppctl [NAME]                     - Get a vppctl shell on specific node"
    echo "$(basename -- $0) sh [vpp|node] [NAME]              - Get a shell in vpp (dataplane) or calico-node (controlplane) container"
    echo "$(basename -- $0) log [vpp|node] [NAME]             - Get the logs of vpp (dataplane) or calico-node (controlplane) container"
    echo "$(basename -- $0) tail [vpp|node] [NAME]            - tail -f the logs of vpp (dataplane) or calico-node (controlplane) container"
  fi
}

vppdev_cli $@
