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

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function green () { printf "\e[0;32m$1\e[0m\n" ; }
function red   () { printf "\e[0;31m$1\e[0m\n" ; }
function blue  () { printf "\e[0;34m$1\e[0m\n" ; }
function grey  () { printf "\e[0;37m$1\e[0m\n" ; }
function greychr  () { printf "\e[0;37m$1\e[0m" ; }
function greydot  () { printf "\e[0;37m.\e[0m" ; }

# Common function to map interface types to VPP graph input node
# Sets global variables: vpp_input_node and interface (if empty)
map_interface_type ()
{
  local interface_param="$1"

  if [ x"$interface_param" != x ]; then
    case "$interface_param" in
    phy)
      # Get the actual VPP driver from the ConfigMap
      local actual_driver=$(get_vpp_driver_from_configmap)
      if [ $? -ne 0 ]; then
        red "Failed to get VPP driver from ConfigMap: $actual_driver"
        exit 1
      fi
      # Recursively call with the actual driver
      map_interface_type "$actual_driver"
      return
      ;;
    af_xdp)
      vpp_input_node="af-xdp-input"
      interface="af_xdp"
      ;;
    af_packet)
      vpp_input_node="af-packet-input"
      interface="af_packet"
      ;;
    avf)
      vpp_input_node="avf-input"
      interface="avf"
      ;;
    vmxnet3)
      vpp_input_node="vmxnet3-input"
      interface="vmxnet3"
      ;;
    virtio|tuntap)
      vpp_input_node="virtio-input"
      interface="virtio"
      ;;
    rdma)
      vpp_input_node="rdma-input"
      interface="rdma"
      ;;
    dpdk)
      vpp_input_node="dpdk-input"
      interface="dpdk"
      ;;
    memif)
      vpp_input_node="memif-input"
      interface="memif"
      ;;
    vcl)
      vpp_input_node="session-queue"
      interface="vcl"
      ;;
    *)
      red "Invalid interface type: $interface_param"
      echo ""
      echo "Supported interface types:"
      echo "  phy       : use the physical interface driver configured in calico-vpp-config"
      echo "  af_xdp    : use an AF_XDP socket to drive the interface"
      echo "  af_packet : use an AF_PACKET socket to drive the interface"
      echo "  avf       : use the VPP native driver for Intel 700-Series and 800-Series interfaces"
      echo "  vmxnet3   : use the VPP native driver for VMware virtual interfaces"
      echo "  virtio    : use the VPP native driver for Virtio virtual interfaces"
      echo "  tuntap    : alias for virtio (default)"
      echo "  rdma      : use the VPP native driver for Mellanox CX-4 and CX-5 interfaces"
      echo "  dpdk      : use the DPDK interface drivers with VPP"
      echo "  memif     : use shared memory interfaces (memif)"
      echo "  vcl       : capture packets at the session layer"
      echo ""
      echo "Default: virtio (if no interface type is specified)"
      exit 1
      ;;
    esac
  else
    vpp_input_node="virtio-input"  # default to virtio
    interface="virtio"
  fi
}

# Function to retrieve the vppDriver from the calico-vpp-config ConfigMap
get_vpp_driver_from_configmap ()
{
  local interfaces_data
  local driver

  # Get the CALICOVPP_INTERFACES data from the ConfigMap
  interfaces_data=$(kubectl get configmap calico-vpp-config -n calico-vpp-dataplane -o jsonpath='{.data.CALICOVPP_INTERFACES}' 2>/dev/null)

  if [ $? -ne 0 ] || [ -z "$interfaces_data" ]; then
    echo "Failed to get calico-vpp-config ConfigMap or CALICOVPP_INTERFACES not found" >&2
    return 1
  fi

  # Parse the JSON to extract the vppDriver from the first uplink interface
  driver=$(echo "$interfaces_data" | jq -r '.uplinkInterfaces[0].vppDriver // empty' 2>/dev/null)

  if [ $? -ne 0 ]; then
    echo "Failed to parse CALICOVPP_INTERFACES JSON (jq command failed)" >&2
    return 1
  fi

  if [ -z "$driver" ]; then
    echo "vppDriver not found or is empty in configuration" >&2
    return 1
  fi

  # Trim whitespace and return the driver
  driver=$(echo "$driver" | tr -d '[:space:]')
  echo "$driver"
  return 0
}

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
  NODE=$NODE SVC=calico-vpp-dataplane POD=calico-vpp-node C=vpp exec_node \
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
	if [ x$(kubectl -n calico-vpp-dataplane get pods | grep calico-vpp | wc -l) = x0 ]; then
		red "No calico-vpp pod found"
		exit 1
	fi

	DIR=$1
	PREFIX=$2
	DIR=${DIR:=./export}
	mkdir -p $DIR
	green "Exporting to $DIR"

	greychr "Logging k8 internals..."
    local operator_pod_name=$(kubectl -n tigera-operator get pods -o name)

	kubectl version                                                         > ${DIR}/${PREFIX}kubectl-version                 ; greydot
	sudo journalctl -u kubelet -r -n200                                     > ${DIR}/${PREFIX}kubelet-journal 2>&1            ; greydot
	kubectl                         get pods -o wide -A                     > ${DIR}/${PREFIX}get-pods                        ; greydot
	kubectl                         get services -o wide -A                 > ${DIR}/${PREFIX}get-services                    ; greydot
	kubectl                         get nodes -o wide                       > ${DIR}/${PREFIX}get-nodes                       ; greydot
	kubectl                         get installation -o yaml                > ${DIR}/${PREFIX}installation.yaml               ; greydot
	kubectl -n calico-system        get configmap cni-config -o yaml        > ${DIR}/${PREFIX}cni-config.configmap.yaml       ; greydot
	kubectl -n calico-vpp-dataplane get daemonset calico-vpp-node -o yaml   > ${DIR}/${PREFIX}calico-vpp-node.daemonset.yaml  ; greydot
	kubectl -n calico-vpp-dataplane get configmap calico-vpp-config -o yaml > ${DIR}/${PREFIX}calico-vpp-node.daemonset.yaml  ; greydot
	kubectl -n tigera-operator      logs $operator_pod_name					> ${DIR}/${PREFIX}operator.log 					  ; greydot
	printf '\n'

	for node in $(get_available_node_names)
	do
		greychr "Dumping node '$node' stats..."
		local calico_pod_name=$(POD=calico-node NODE=$node SVC=calico-system find_node_pod)
		local calicovpp_pod_name=$(POD=calico-vpp-node NODE=$node SVC=calico-vpp-dataplane find_node_pod)
		NODE=$node vppctl show hardware-interfaces                    > ${DIR}/${PREFIX}${node}.hardware-interfaces   ; greydot
		NODE=$node vppctl show run                                    > ${DIR}/${PREFIX}${node}.show-run              ; greydot
		NODE=$node vppctl show err                                    > ${DIR}/${PREFIX}${node}.show-err              ; greydot
		NODE=$node vppctl show log                                    > ${DIR}/${PREFIX}${node}.show-log              ; greydot
		NODE=$node vppctl show buffers                                > ${DIR}/${PREFIX}${node}.show-buffers          ; greydot
		NODE=$node vppctl show int                                    > ${DIR}/${PREFIX}${node}.show-int              ; greydot
		NODE=$node vppctl show int rx                                 > ${DIR}/${PREFIX}${node}.show-int-rx           ; greydot
		NODE=$node vppctl show tun                                    > ${DIR}/${PREFIX}${node}.show-tun              ; greydot
		printf '\n'
		greychr "Dumping node '$node' calico logs..."
		kubectl -n calico-system describe pod/$calico_pod_name              > ${DIR}/${PREFIX}${node}.describe-calico-node-pod ; greydot
		NODE=$node SVC=calico-system POD=calico-node C=calico-node log_node > ${DIR}/${PREFIX}${node}.calico-node.log          ; greydot
		printf '\n'
		greychr "Dumping node '$node' vpp logs..."
		kubectl -n calico-vpp-dataplane describe pod/$calicovpp_pod_name         > ${DIR}/${PREFIX}${node}.describe-vpp-pod    ; greydot
		NODE=$node SVC=calico-vpp-dataplane POD=calico-vpp-node C=vpp log_node   > ${DIR}/${PREFIX}${node}.vpp.log             ; greydot
		NODE=$node SVC=calico-vpp-dataplane POD=calico-vpp-node C=agent log_node > ${DIR}/${PREFIX}${node}.agent.log           ; greydot
		printf '\n'
		greychr "Dumping node '$node' state..."
		NODE=$node vppctl show cnat client                            > ${DIR}/${PREFIX}${node}.show-cnat-client      ; greydot
		NODE=$node vppctl show cnat translation                       > ${DIR}/${PREFIX}${node}.show-cnat-translation ; greydot
		NODE=$node vppctl show cnat session verbose                   > ${DIR}/${PREFIX}${node}.show-cnat-session     ; greydot
		NODE=$node vppctl show cnat timestamp                         > ${DIR}/${PREFIX}${node}.show-cnat-timestamp   ; greydot
		NODE=$node vppctl show cnat snat                              > ${DIR}/${PREFIX}${node}.show-cnat-snat        ; greydot
		printf '\n'
		greychr "Dumping node '$node' policies..."
		NODE=$node vppctl show capo interfaces                        > ${DIR}/${PREFIX}${node}.show-capo-interfaces  ; greydot
		NODE=$node vppctl show capo policies verbose                  > ${DIR}/${PREFIX}${node}.show-capo-policies    ; greydot
		NODE=$node vppctl show capo rules                             > ${DIR}/${PREFIX}${node}.show-capo-rules       ; greydot
		NODE=$node vppctl show capo ipsets                            > ${DIR}/${PREFIX}${node}.show-capo-ipsets      ; greydot
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
	if [ x$(kubectl -n calico-vpp-dataplane get pods | grep calico-vpp | wc -l) = x0 ]; then
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
  SVC=calico-vpp-dataplane NODE=$NODE POD=calico-vpp-node C=vpp FOLLOW=$FOLLOW log_node
}

print_agent_logs ()
{
  SVC=calico-vpp-dataplane NODE=$NODE POD=calico-vpp-node C=agent FOLLOW=$FOLLOW log_node
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
	NODE=$2 SVC=calico-vpp-dataplane POD=calico-vpp-node C=vpp exec_node bash
  elif [[ "$1" = "agent" ]]; then
	grey "This shell lives inside the agent container"
	grey "You will find calico-vpp-agent & felix running"
	NODE=$2 SVC=calico-vpp-dataplane POD=calico-vpp-node C=agent exec_node bash
  else
	echo "Use $(basename -- $0) sh [vpp|agent] [NODENAME]"
  fi
}

vppdev_cli_orch ()
{
  $SCRIPTDIR/orch.sh $@
}

vppdev_cli_tst ()
{
  $SCRIPTDIR/test.sh $@
}

vppdev_cli_cases ()
{
  $SCRIPTDIR/cases.sh $@
}

vppdev_cli_ci ()
{
  $SCRIPTDIR/ci.sh $@
}

vppdev_cli_push ()
{
  $SCRIPTDIR/mngmt.sh push $@
}

compress_and_save_remote_file ()
{
  local node="$1"
  local remote_file="$2"
  local local_file="$3"
  local namespace="calico-vpp-dataplane"
  local container="vpp"

  # Find the pod on the specified node
  local pod_name=$(SVC=calico-vpp-dataplane POD=calico-vpp-node find_node_pod)
  if [ x"$pod_name" = x ]; then
    red "Could not find calico-vpp-node pod on node '$node'"
    return 1
  fi

  green "Compressing and downloading file from node '$node'"
  grey "Pod: $pod_name"
  grey "Remote file: $remote_file"
  grey "Local file: $local_file"
  echo

  blue "Compressing remote file..."
  kubectl exec -n $namespace $pod_name -c $container -- sh -c "gzip -c $remote_file > /tmp/$(basename $remote_file).gz"

  blue "Copying compressed file..."
  kubectl cp $namespace/$pod_name:/tmp/$(basename $remote_file).gz $local_file -c $container

  if [ $? -eq 0 ]; then
    green "File successfully saved to $local_file"
  else
    red "Failed to save file"
    return 1
  fi

  blue "Cleaning up remote file..."
  kubectl exec -n $namespace $pod_name -c $container -- sh -c "rm -f $remote_file"
  kubectl exec -n $namespace $pod_name -c $container -- sh -c "rm -f /tmp/$(basename $remote_file).gz"
}

vppdev_cli_trace ()
{
  local node=""
  local count="1000"
  local interface=""
  local vpp_input_node=""

  # First argument is the node name (if not starting with -)
  if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
    node="$1"
    shift
  fi

  # Parse remaining arguments
  while (( $# )); do
    case "$1" in
    -c|-count)
      count="$2"
      shift 2
      ;;
    -i|-interface)
      interface="$2"
      shift 2
      ;;
    *)
      red "Unknown option: $1"
      echo "Usage: $(basename -- $0) trace [NODENAME] [-count N] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl]"
      exit 1
      ;;
    esac
  done

  # Validate required parameters
  if [ x"$node" = x ]; then
    red "Node name is required"
    echo "Usage: $(basename -- $0) trace [NODENAME] [-count N] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl]"
    exit 1
  fi

  # Set NODE for validation
  NODE="$node"
  validate_node_name

  # Map interface type to VPP graph input node
  map_interface_type "$interface"

  local trace_command="trace add $vpp_input_node $count"

  green "Starting packet trace on node '$NODE'"
  grey "Packet count: $count"
  if [ x"$interface" != x ]; then
    grey "VPP Input Node: $vpp_input_node"
  fi
  grey "Output file: ./trace.txt.gz"
  echo

  # Clear any existing traces first
  NODE="$NODE" vppctl clear trace

  blue "Starting packet trace..."
  grey "Command: $trace_command"
  NODE="$NODE" vppctl $trace_command

  echo
  blue "Packet trace configured. Press Ctrl+C to stop tracing and save output..."
  echo

  # Set up trap to handle Ctrl+C
  trap 'echo; \
        blue "Stopping trace..."; \
        local pod_name=$(SVC=calico-vpp-dataplane POD=calico-vpp-node find_node_pod); \
        kubectl exec -n calico-vpp-dataplane $pod_name -c vpp -- sh -c "vppctl -s /var/run/vpp/cli.sock show trace max '"$count"' > /tmp/trace.txt"; \
        NODE="$NODE" vppctl clear trace; \
        compress_and_save_remote_file "$NODE" "/tmp/trace.txt" "./trace.txt.gz"; \
        exit 0;' INT

  # Keep checking for trace activity in a loop
  while true; do
    sleep 5
    green "=== Packet trace active on node '$NODE' (Press Ctrl+C to stop) ==="
    echo
  done
}

vppdev_cli_pcap ()
{
  local node=""
  local count="1000"
  local interface=""
  local interface_name=""
  local output_file=""

  # First argument is the node name (if not starting with -)
  if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
    node="$1"
    shift
  fi

  # Parse remaining arguments
  while (( $# )); do
    case "$1" in
    -c|-count)
      count="$2"
      shift 2
      ;;
    -i|-interface)
      interface="$2"
      shift 2
      ;;
    -o|-output)
      output_file="$2"
      shift 2
      ;;
    *)
      red "Unknown option: $1"
      echo "Usage: $(basename -- $0) pcap [NODENAME] [-count N] [-interface INTERFACE_NAME|any(default)] [-output FILE.pcap]"
      exit 1
      ;;
    esac
  done

  # Validate required parameters
  if [ x"$node" = x ]; then
    red "Node name is required"
    echo "Usage: $(basename -- $0) pcap [NODENAME] [-count N] [-interface INTERFACE_NAME|any(default)] [-output FILE.pcap]"
    exit 1
  fi

  # Set NODE for validation
  NODE="$node"
  validate_node_name

  # First, let's validate that we can access the VPP interfaces
  local interfaces_output=$(NODE="$NODE" vppctl show interface 2>/dev/null)
  if [[ $? -ne 0 ]]; then
    red "Failed to get interface list from VPP"
    exit 1
  fi

  local up_interfaces=$(parse_vpp_interfaces "$interfaces_output")
  if [[ -z "$up_interfaces" ]]; then
    red "No interfaces found or all interfaces are down on node '$NODE'"
    exit 1
  fi

  # Validate and set VPP input node
  if [[ -n "$interface" ]]; then
    # Check if the provided interface name exists in the UP interfaces list
    local is_valid_interface=false
    for iface in $up_interfaces; do
      if [[ "$iface" == "$interface" ]]; then
        is_valid_interface=true
        break
      fi
    done

    if [[ "$is_valid_interface" == true ]]; then
      # User provided a valid interface name
      interface_name="$interface"
    else
      # Interface not found, show available UP interfaces
      red "Interface '$interface' not found or is down."
      echo "Available UP interfaces:"
      local count=1
      for iface in $up_interfaces; do
        echo "$count. $iface"
        ((count++))
      done
      exit 1
    fi
  else
    # No interface specified, use "any" to capture on all interfaces
    interface_name="any"
    grey "No interface specified, using 'any' to capture on all interfaces"
  fi

  local pcap_command="pcap trace tx rx max $count intfc $interface_name file trace.pcap"

  green "Starting PCAP trace on node '$NODE'"
  grey "Packet count: $count"
  grey "Interface Name: $interface_name"
  if [ x"$output_file" != x ]; then
    grey "Output file: ./${output_file}.gz"
  fi
  echo

  blue "Starting PCAP trace..."
  grey "Command: $pcap_command"
  NODE="$NODE" vppctl $pcap_command

  echo
  blue "PCAP trace configured. Press Ctrl+C to stop tracing..."
  echo

  # Determine output filename
  local local_output_file
  if [ x"$output_file" != x ]; then
    local_output_file="./${output_file}.gz"
  else
    local_output_file="./pcap_${NODE}.pcap.gz"
  fi

  # Set up trap to handle Ctrl+C
  trap 'echo; \
        blue "Stopping PCAP trace..."; \
        NODE="$NODE" vppctl pcap trace off; \
        green "PCAP trace stopped"; echo; \
        compress_and_save_remote_file "$NODE" "/tmp/trace.pcap" \
                                      "'"$local_output_file"'"; \
        exit 0;' INT

  # Keep the script running until Ctrl+C
  while true; do
    sleep 5
    green "=== PCAP trace active on node '$NODE' (Press Ctrl+C to stop) ==="
    echo
  done
}

vppdev_cli_dispatch ()
{
  local node=""
  local count="1000"
  local interface=""
  local vpp_input_node=""
  local output_file=""

  # First argument is the node name (if not starting with -)
  if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
    node="$1"
    shift
  fi

  # Parse remaining arguments
  while (( $# )); do
    case "$1" in
    -c|-count)
      count="$2"
      shift 2
      ;;
    -i|-interface)
      interface="$2"
      shift 2
      ;;
    -o|-output)
      output_file="$2"
      shift 2
      ;;
    *)
      red "Unknown option: $1"
      echo "Usage: $(basename -- $0) dispatch [NODENAME] [-count N] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl] [-output FILE.pcap]"
      exit 1
      ;;
    esac
  done

  # Validate required parameters
  if [ x"$node" = x ]; then
    red "Node name is required"
    echo "Usage: $(basename -- $0) dispatch [NODENAME] [-count N] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl] [-output FILE.pcap]"
    exit 1
  fi

  # Set NODE for validation
  NODE="$node"
  validate_node_name

  # Map interface type to VPP graph input node
  # For dispatch tracing, we still use interface types (memif, tuntap, vcl)
  # as dispatch tracing works differently than pcap tracing
  map_interface_type "$interface"

  local dispatch_command="pcap dispatch trace on max $count buffer-trace $vpp_input_node $count"

  green "Starting dispatch trace on node '$NODE'"
  grey "Packet count: $count"
  if [ x"$interface" != x ]; then
    grey "VPP Input Node: $vpp_input_node"
  fi
  if [ x"$output_file" != x ]; then
    grey "Output file: ./${output_file}.gz"
  fi
  echo

  blue "Starting dispatch trace..."
  grey "Command: $dispatch_command"
  NODE="$NODE" vppctl $dispatch_command

  echo
  blue "Dispatch trace configured. Press Ctrl+C to stop tracing..."
  echo

  # Determine output filename
  local local_output_file
  if [ x"$output_file" != x ]; then
    local_output_file="./${output_file}.gz"
  else
    local_output_file="./dispatch_${NODE}.pcap.gz"
  fi

  # Set up trap to handle Ctrl+C
  trap 'echo; \
        blue "Stopping dispatch trace..."; \
        NODE="$NODE" vppctl pcap dispatch trace off; \
        green "Dispatch trace stopped"; echo; \
        compress_and_save_remote_file "$NODE" "/tmp/dispatch.pcap" \
                                      "'"$local_output_file"'"; \
        exit 0;' INT

  # Keep the script running until Ctrl+C
  while true; do
    sleep 5
    green "=== Dispatch trace active on node '$NODE' (Press Ctrl+C to stop) ==="
    echo
  done
}

# Parse VPP interfaces from "show interface" output and return list of UP interfaces
parse_vpp_interfaces ()
{
  local output="$1"
  local up_interfaces=""

  while IFS= read -r line; do
    # Skip empty lines and header lines
    if [[ -z "${line// }" ]] || [[ "$line" == *"Name"* ]] || [[ "$line" == *"Counter"* ]] || [[ "$line" == *"Count"* ]]; then
      continue
    fi

    # Skip lines that don't start with an interface name (statistics lines, etc.)
    local trimmed=$(echo "$line" | sed 's/^[[:space:]]*//')
    if [[ "$trimmed" =~ ^(rx |tx |drops|punt|ip4|ip6) ]]; then
      continue
    fi

    # Look for interface lines (they start with interface name)
    # Format: "interface_name    idx    state    mtu"
    local fields=($line)
    if [[ ${#fields[@]} -ge 3 ]]; then
      local interface_name="${fields[0]}"
      local state="${fields[2]}"

      # Only add interfaces that are "up"
      if [[ "$state" == "up" ]] && [[ -n "$interface_name" ]]; then
        if [[ -z "$up_interfaces" ]]; then
          up_interfaces="$interface_name"
        else
          up_interfaces="$up_interfaces $interface_name"
        fi
      fi
    fi
  done <<< "$output"

  echo "$up_interfaces"
}

# Validate that the provided interface exists and is up
validate_interface ()
{
  local node="$1"
  local interface_name="$2"

  if [[ -z "$interface_name" ]]; then
    return 0  # No interface specified, allow default behavior
  fi

  # Get the list of interfaces from VPP
  local output=$(NODE="$node" vppctl show interface 2>/dev/null)
  if [[ $? -ne 0 ]]; then
    red "Failed to get interface list from VPP"
    return 1
  fi

  # Parse the interfaces
  local up_interfaces=$(parse_vpp_interfaces "$output")

  if [[ -z "$up_interfaces" ]]; then
    red "No interfaces found or all interfaces are down"
    return 1
  fi

  # Check if the specified interface is in the list
  for iface in $up_interfaces; do
    if [[ "$iface" == "$interface_name" ]]; then
      return 0  # Interface found and is up
    fi
  done

  # Interface not found, provide helpful error message
  red "Interface '$interface_name' not found or is down."
  echo "Available UP interfaces:"
  local count=1
  for iface in $up_interfaces; do
    echo "$count. $iface"
    ((count++))
  done
  return 1
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
    echo "$(basename -- $0) clear                             - Clear vpp internal stats"
    echo "$(basename -- $0) export                            - Create an archive with vpp & k8 system state for debugging"
    echo "                                                    it accepts a dir name and a prefix 'export [dir] [prefix]'"
    echo "$(basename -- $0) gdb                               - Attach a gdb to the running vpp on the current machine"
    echo "$(basename -- $0) sh [vpp|agent] [NODENAME]         - Get a shell in vpp (dataplane) or agent (controlplane) container"
    echo "$(basename -- $0) trace [NODENAME]                  - Setup VPP packet tracing"
    echo "       Optional params: [-count N] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl]"
    echo "$(basename -- $0) pcap [NODENAME]                    - Setup VPP PCAP tracing"
    echo "       Optional params: [-count N] [-interface INTERFACE_NAME|any(default)] [-output FILE.pcap]"
    echo "$(basename -- $0) dispatch [NODENAME]                - Setup VPP dispatch tracing"
    echo "       Optional params: [-count N] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl] [-output FILE.pcap]"
    if [[ -f $SCRIPTDIR/ci.sh ]]; then # only if we have the whole repo
    	echo
    	echo
    	echo "$(basename -- $0) orch                              - Provision test clusters with kubeadm"
    	echo "$(basename -- $0) tst                               - Deploy test pods"
    	echo "$(basename -- $0) cases                             - Run test cases using deployed test pods"
    	echo "$(basename -- $0) ci                                - Simple CI doing provision cluster/pods/testcases"
    	echo "$(basename -- $0) push                              - Push images"
	fi
    echo
  fi
}

vppdev_cli $@
