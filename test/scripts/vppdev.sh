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

set +x

function green () { printf "\e[0;32m$1\e[0m\n" ; }
function red   () { printf "\e[0;31m$1\e[0m\n" ; }
function blue  () { printf "\e[0;34m$1\e[0m\n" ; }
function grey  () { printf "\e[0;37m$1\e[0m\n" ; }
function greychr  () { printf "\e[0;37m$1\e[0m" ; }
function greydot  () { printf "\e[0;37m.\e[0m" ; }

get_available_node_names ()
{
  kubectl get nodes -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}'
}

validate_node_name ()
{
  local node_names=$(get_available_node_names)
  local node_cnt=$(get_available_node_names | wc -l)

  if [ "x$node_names" = x ];
  then
  	red "No nodes found. Is cluster running ?"
  	exit 1
  fi

  if [ x$node_cnt = x1 ] && [ x$NODE = x ]; then
    NODE=$node_names
    return
  fi

  for n in $node_names
  do
	if [ x$NODE = x$n ]; then
      return
	fi
  done

  >&2 red "Please specify a node name :"
  for n in $node_names
  do
	>&2 echo "$n"
  done
  exit 1
}

find_node_pod () # NODE, POD
{
  SVC=${SVC:=kube-system}
  echo $(kubectl get pods -n $SVC --field-selector="spec.nodeName=$NODE" | grep $POD | cut -d ' ' -f 1)
}

exec_node () # C, POD, NODE
{
  validate_node_name
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
  validate_node_name
  SVC=${SVC:=kube-system}
  local pod_name=$(find_node_pod)
  if [ x"$pod_name" == x ]; then
    >&2 red "pod '$POD' not found on node '$NODE'"
  	exit 1
  else
	kubectl logs $FOLLOW -n $SVC $pod_name -c ${C:-''}
  fi
}

vppctl () # nodeID args
{
  NODE=$NODE POD=calico-vpp-node C=vpp exec_node \
	/usr/bin/vppctl -s /var/run/vpp/cli.sock $@
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
	green "Exporting to $DIR"

	greychr "Logging k8 internals..."

	kubectl version                                              > ${DIR}/${PREFIX}kubectl-version                 ; greydot
	sudo journalctl -u kubelet -r -n200                          > ${DIR}/${PREFIX}kubelet-journal 2>&1            ; greydot
	kubectl -n kube-system get pods -o wide                      > ${DIR}/${PREFIX}get-pods                        ; greydot
	kubectl -n kube-system get services -o wide                  > ${DIR}/${PREFIX}get-services                    ; greydot
	kubectl -n kube-system get nodes -o wide                     > ${DIR}/${PREFIX}get-nodes                       ; greydot
	kubectl -n kube-system get configmap calico-config -o yaml   > ${DIR}/${PREFIX}calico-config.configmap.yaml    ; greydot
	kubectl -n kube-system get daemonset calico-vpp-node -o yaml > ${DIR}/${PREFIX}calico-vpp-node.daemonset.yaml  ; greydot
	printf '\n'

	for node in $(get_available_node_names)
	do
		greychr "Dumping node '$node' stats..."
		local calicovpp_pod_name=$(POD=calico-vpp-node NODE=$node find_node_pod)
		NODE=$node vppctl show hardware-interfaces                    > ${DIR}/${PREFIX}${node}.hardware-interfaces   ; greydot
		NODE=$node vppctl show run                                    > ${DIR}/${PREFIX}${node}.show-run              ; greydot
		NODE=$node vppctl show err                                    > ${DIR}/${PREFIX}${node}.show-err              ; greydot
		NODE=$node vppctl show log                                    > ${DIR}/${PREFIX}${node}.show-log              ; greydot
		NODE=$node vppctl show buffers                                > ${DIR}/${PREFIX}${node}.show-buffers          ; greydot
		NODE=$node vppctl show int                                    > ${DIR}/${PREFIX}${node}.show-int              ; greydot
		NODE=$node vppctl show int rx                                 > ${DIR}/${PREFIX}${node}.show-int-rx           ; greydot
		NODE=$node vppctl show tun                                    > ${DIR}/${PREFIX}${node}.show-tun              ; greydot
		printf '\n'
		greychr "Dumping node '$node' logs..."
		kubectl -n kube-system describe pod/$calicovpp_pod_name       > ${DIR}/${PREFIX}${node}.describe-vpp-pod      ; greydot
		NODE=$node POD=calico-vpp-node C=vpp log_node                 > ${DIR}/${PREFIX}${node}.vpp.log               ; greydot
		NODE=$node POD=calico-vpp-node C=agent log_node               > ${DIR}/${PREFIX}${node}.calico.log            ; greydot
		printf '\n'
		greychr "Dumping node '$node' state..."
		NODE=$node vppctl show cnat client                            > ${DIR}/${PREFIX}${node}.show-cnat-client      ; greydot
		NODE=$node vppctl show cnat translation                       > ${DIR}/${PREFIX}${node}.show-cnat-translation ; greydot
		NODE=$node vppctl show cnat session verbose                   > ${DIR}/${PREFIX}${node}.show-cnat-session     ; greydot
		NODE=$node vppctl show cnat timestamp                         > ${DIR}/${PREFIX}${node}.show-cnat-timestamp   ; greydot
		NODE=$node vppctl show cnat snat                              > ${DIR}/${PREFIX}${node}.show-cnat-snat        ; greydot
		printf '\n'
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
	for node in $(get_available_node_names)
	do
		NODE=$node vppctl clear run
		NODE=$node vppctl clear err
	done
}

vppdev_cli_vppctl ()
{
  NODE=$1; shift
  validate_node_name
  NODE=$NODE vppctl $@
}

print_vpp_logs ()
{
  NODE=$NODE POD=calico-vpp-node C=vpp FOLLOW=$FOLLOW log_node
}

print_agent_logs ()
{
  NODE=$NODE POD=calico-vpp-node C=agent FOLLOW=$FOLLOW log_node | grep --color=Never -e '^time='
}

print_felix_logs ()
{
  NODE=$NODE POD=calico-node C= FOLLOW=$FOLLOW log_node | grep --color=Never -v -e '^time='
}

vppdev_cli_log ()
{
	local log=""
	local FOLLOW=""
	while (( $# )); do
		case "$1" in
		-vpp)
			log=vpp
			shift
			;;
		-agent)
			log=agent
			shift
			;;
		-felix)
			log=felix
			shift
			;;
		-f)
			FOLLOW="-f"
			shift
			;;
		*)
        	NODE=$1
			shift
			;;
		esac
	done

	validate_node_name

	if [ x$log = x ]; then
	  FOLLOW=""
	  blue "----- Felix -----"
	  print_felix_logs
	  blue "----- VPP Manager      -----"
	  print_vpp_logs
	  blue "----- Calico-VPP agent -----"
	  print_agent_logs
	else
	  print_${log}_logs
	fi
}

vppdev_cli_sh ()
{
  if [[ "$1" = "vpp" ]]; then
	grey "This shell lives inside the vpp container"
	grey "You will find vpp-manager & vpp running"
	NODE=$2 POD=calico-vpp-node C=vpp exec_node bash
  elif [[ "$1" = "agent" ]]; then
	grey "This shell lives inside the agent container"
	grey "You will find calico-vpp-agent & felix running"
	NODE=$2 POD=calico-vpp-node C=agent exec_node bash
  else
	echo "Use $(basename -- $0) sh [vpp|agent] [NODENAME]"
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
    echo "$(basename -- $0) log [-f] [-vpp|-agent] [NODENAME] - Get the logs of vpp (dataplane) or agent (controlplane) container"
    echo
    echo "$(basename -- $0) clear                             - Clear vpp internal stats"
    echo "$(basename -- $0) export                            - Create an archive with vpp & k8 system state for debugging"
    echo "                                                    it accepts a dir name and a prefix 'export [dir] [prefix]'"
	echo
    echo "$(basename -- $0) gdb                               - Attach a gdb to the running vpp on the current machine"
    echo "$(basename -- $0) sh [vpp|agent] [NODENAME]         - Get a shell in vpp (dataplane) or agent (controlplane) container"
  fi
}

vppdev_cli $@
