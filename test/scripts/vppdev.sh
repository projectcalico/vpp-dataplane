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
    >&2 red "pod '$POD' not found on node '$NODE'"
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
    >&2 red "pod '$POD' not found on node '$NODE'"
  	exit 1
  else
	kubectl logs $FOLLOW -n $SVC $pod_name -c $C
  fi
}

vppctl () # nodeID args
{
  NODE=$1 POD=calico-vpp-node C=vpp exec_node \
	/usr/bin/vppctl -s /var/run/vpp/cli.sock ${@:2}
}

#
# CLI functions
#

vppdev_cli_gdb ()
{
  grey "This finds the VPP running in a vpp_calico-vpp docker container"
  grey "and attaches to it. [Ctrl+C detach q ENTER] to exit"
  local container=$(docker ps | grep vpp_calico-vpp | awk '{ print $1 }')
  if [ x$container == x ]; then
  	red "No vpp container found"
  	exit 1
  fi
  local pid=$(docker exec -it $container cat /var/run/vpp/vpp.pid)
  docker exec -it $container gdb -p $pid -ex continue
}

vppdev_cli_export ()
{
	kubectl version > /dev/null 2>&1
	if [ $? != 0 ]; then
		red "Couldn't connect to kubernetes using kubectl"
		exit 1
	fi
	if [ x$(kubectl -n kube-system get pods | grep calico-vpp | wc -l) = x0 ]; then
		red "No calico-vpp pod found"
		exit 1
	fi

	DIR=$1
	PREFIX=$2
	DIR=${DIR:=./export}
	mkdir -p $DIR

	grey "Logging k8 internals..."

	kubectl version                                              > ${DIR}/${PREFIX}kubectl-version
	sudo journalctl -u kubelet -r -n200                          > ${DIR}/${PREFIX}kubelet-journal 2>&1
	kubectl -n kube-system get pods -o wide                      > ${DIR}/${PREFIX}get-pods
	kubectl -n kube-system get services -o wide                  > ${DIR}/${PREFIX}get-services
	kubectl -n kube-system get nodes -o wide                     > ${DIR}/${PREFIX}get-nodes
	kubectl -n kube-system get configmap calico-config -o yaml   > ${DIR}/${PREFIX}calico-config.configmap.yaml
	kubectl -n kube-system get daemonset calico-vpp-node -o yaml > ${DIR}/${PREFIX}calico-vpp-node.daemonset.yaml

	for node in $(kubectl get nodes -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}')
	do
		grey "Logging node $node..."
		local calicovpp_pod_name=$(POD=calico-vpp-node NODE=$node find_node_pod)
		vppctl $node show hardware-interfaces                    > ${DIR}/${PREFIX}${node}.hardware-interfaces
		vppctl $node show run                                    > ${DIR}/${PREFIX}${node}.show-run
		vppctl $node show err                                    > ${DIR}/${PREFIX}${node}.show-err
		vppctl $node show log                                    > ${DIR}/${PREFIX}${node}.show-log
		vppctl $node show buffers                                > ${DIR}/${PREFIX}${node}.show-buffers
		vppctl $node show int                                    > ${DIR}/${PREFIX}${node}.show-int
		vppctl $node show int rx                                 > ${DIR}/${PREFIX}${node}.show-int-rx
		vppctl $node show tun                                    > ${DIR}/${PREFIX}${node}.show-tun
		kubectl -n kube-system describe pod/$calicovpp_pod_name  > ${DIR}/${PREFIX}${node}.describe-vpp-pod
		NODE=$node POD=calico-vpp-node C=vpp log_node            > ${DIR}/${PREFIX}${node}.vpp.log
		NODE=$node POD=calico-vpp-node C=calico-node log_node    > ${DIR}/${PREFIX}${node}.calico.log
		NODE=$node POD=calico-vpp-node C=calico-node exec_node \
		  cat /var/log/calico/calico-vpp-agent/current           > ${DIR}/${PREFIX}${node}.agent.log
	done
	# By default, compress to archive
	if [ x$DIR = x./export ]; then
		grey "compressing..."
		tar -zcvf ./export.tar.gz ./export > /dev/null
		rm -r ./export
		green "Done exporting to ./export.tar.gz"
	else
		green "Done exporting to $DIR"
	fi
}

vppdev_cli_clear ()
{
	if [ x$(kubectl -n kube-system get pods | grep calico-vpp | wc -l) = x0 ]; then
		echo "No calico-vpp pod found"
		exit 1
	fi
	for node in $(kubectl get nodes -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}')
	do
		vppctl $node clear run
		vppctl $node clear err
	done
}

vppdev_cli_vppctl ()
{
  vppctl $@
}

vppdev_cli_log ()
{
	local container=""
	local FOLLOW=""
	local node_name=""
	local cattail="cat"
	while (( $# )); do
		case "$1" in
		-vpp)
			container=vpp
			shift
			;;
		-agent)
			container=agent
			shift
			;;
		-f)
			FOLLOW="-f"
			cattail="tail -f"
			shift
			;;
		*)
        	node_name=$1
			shift
			;;
		esac
	done

	if [ x$node_name = x ]; then
		red "Please specify a node name"
		exit 1
	fi

	if [[ "$container" = "vpp" ]]; then
	  NODE=$node_name POD=calico-vpp-node C=vpp FOLLOW=$FOLLOW log_node
	elif [[ "$container" = "agent" ]]; then
	  NODE=$node_name POD=calico-vpp-node C=calico-node exec_node \
    	$cattail /var/log/calico/calico-vpp-agent/current
	else
	  blue "----- VPP Manager      -----"
	  NODE=$node_name POD=calico-vpp-node C=vpp log_node
	  blue "----- Calico-VPP agent -----"
	  NODE=$node_name POD=calico-vpp-node C=calico-node exec_node \
    	cat /var/log/calico/calico-vpp-agent/current
	fi
}

vppdev_cli_sh ()
{
  if [[ "$1" = "vpp" ]]; then
	NODE=$2 POD=calico-vpp-node C=vpp exec_node bash
  elif [[ "$1" = "agent" ]]; then
	NODE=$2 POD=calico-vpp-node C=calico-node exec_node bash
  else
  	echo "Use $(basename -- $0) sh [vpp|node] [NODENAME]"
  fi
}

vppdev_cli ()
{
  local fn_name=vppdev_cli_$1
  shift
  if [[ $(declare -F) =~ (^|[[:space:]])"$fn_name"($|[[:space:]]) ]] ; then
    $fn_name $@
  else
	echo '   ______      ___               _    ______  ____ '
	echo '  / ____/___ _/ (_)________     | |  / / __ \/ __ \'
	echo ' / /   / __ `/ / / ___/ __ \    | | / / /_/ / /_/ /'
	echo '/ /___/ /_/ / / / /__/ /_/ /    | |/ / ____/ ____/ '
	echo '\____/\__,_/_/_/\___/\____/     |___/_/   /_/      '
	echo '                                                   '
    echo ""
    echo "Usage:"
    echo
    echo "$(basename -- $0) vppctl [NODENAME]                 - Get a vppctl shell on specific node"
    echo "$(basename -- $0) log [-f] [-vpp|-agent] [NODENAME] - Get the logs of vpp (dataplane) or calico-node (controlplane) container"
    echo
    echo "$(basename -- $0) clear                             - Clear vpp internal stats"
    echo "$(basename -- $0) export                            - Create an archive with vpp & k8 system state for debugging"
    echo "                                                    it accepts a dir name and a prefix 'export [dir] [prefix]'"
	echo
    echo "$(basename -- $0) gdb                               - Attach a gdb to the running vpp on the current machine"
    echo "$(basename -- $0) sh [vpp|agent] [NODENAME]         - Get a shell in vpp (dataplane) or calico-node (controlplane) container"
  fi
}

vppdev_cli $@
