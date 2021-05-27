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

function provision ()
{
  provision_action=$1
  echo "$SCRIPTDIR/provision.sh $provision_action \
    IF=${IF} \
    RENAME_IF=${RENAME_IF} \
	NODE_IP=${NODE_IP} \
	MAIN_NODE_IP=${MAIN_NODE_IP} \
	POD_CIDR=$POD_CIDR \
	SERVICE_CIDR=$SERVICE_CIDR \
	DNS_TYPE=$DNS_TYPE \
	VERBOSE=$VERBOSE \
	K8_VERSION=$K8_VERSION \
	NODE_NAME=$NODE_NAME"
}

function create_k8_cluster () {
	N=1
	NODE_NAME=node$N
	eval $(NODE_IP=${MAIN_IP} MAIN_NODE_IP="" IF=${MAIN_INTERFACE_NAME} RENAME_IF="" provision up)
	ids=""
	for var in ${!JOIN_IP_@}; do
      ids="$ids $(echo $var | awk -F "_" '{print $3}')"
	done

	for i in $ids ; do
		SSH_NAME=$(eval 'echo $JOIN_SSH_'${i})
		NODE_IP=$(eval 'echo $JOIN_IP_'${i})
		NODE_IF=$(eval 'echo $JOIN_IF_'${i})
		N=$((N+1))
		NODE_NAME=node$N
		echo "ssh $SSH_NAME -t $(NODE_IP=$NODE_IP MAIN_NODE_IP=${MAIN_IP%%/*} IF=$NODE_IF RENAME_IF=$MAIN_INTERFACE_NAME provision up)"
		ssh $SSH_NAME -t $(NODE_IP=$NODE_IP MAIN_NODE_IP=${MAIN_IP%%/*} IF=$NODE_IF RENAME_IF=$MAIN_INTERFACE_NAME provision up)
	done
}

function destroy_k8_cluster ()
{
	ids=""
	for var in ${!JOIN_IP_@}; do
      ids="$ids $(echo $var | awk -F "_" '{print $3}')"
	done
	for i in $ids ; do
		SSH_NAME=$(eval 'echo $JOIN_SSH_'${i})
		ssh $SSH_NAME -t $(provision dn)
	done
	eval $(provision dn)
}

function orch_provision_cli ()
{
	NODE_NAME=$(hostname)
	POD_CIDR=10.0.0.0/16
	SERVICE_CIDR=10.96.0.0/16
	DNS_TYPE=CoreDNS
	IS_DUAL=false
	if [[ $1 = up ]]; then
		ACTION=up
	elif [[ $1 = dn ]]; then
		ACTION=dn
	elif [[ $1 = down ]]; then
		ACTION=dn
	elif [[ $1 = template ]]; then
		ACTION=template
	else
		print_usage_and_exit;
	fi
	shift

	while (( "$#" )) ; do
	  	if [[ $1 == *"="* ]]; then
			eval $1
		else
			source $1
		fi
    	shift
	done

	if [[ $ACTION = up ]]; then
		create_k8_cluster
	elif [[ $ACTION = dn ]]; then
		destroy_k8_cluster
	else
		orch_template;
	fi
}

function orch_template ()
{
  echo "K8_VERSION=$(kubectl version -o yaml 2>/dev/null | grep gitVersion | awk '{print $2}')"
  if [[ $V = 6 ]]; then
    echo "POD_CIDR=fd20::0/112"
    echo "SERVICE_CIDR=fd10::0/120"
    echo "MAIN_IP=fd11::1/124"
    echo "MAIN_INTERFACE_NAME=eth0"
    echo "JOIN_IP_1=fd11::2/124"
    echo "JOIN_IF_1=eth0"
    echo "JOIN_SSH_1=somesshnode"
  elif [[ $V = 46 ]]; then
    echo "POD_CIDR=11.0.0.0/16,fd20::0/112"
    echo "SERVICE_CIDR=11.96.0.0/16,fd10::0/120"
    echo "MAIN_IP=20.0.0.1/24,fd11::1/124"
    echo "MAIN_INTERFACE_NAME=eth0"
    echo "JOIN_IP_1=20.0.0.2/24,fd11::2/124"
    echo "JOIN_IF_1=eth0"
    echo "JOIN_SSH_1=somesshnode"
  else
    echo "POD_CIDR=10.0.0.0/16"
    echo "SERVICE_CIDR=10.96.0.0/16"
    echo "MAIN_IP=20.0.0.1/24"
    echo "MAIN_INTERFACE_NAME=eth0"
    echo "JOIN_IP_1=20.0.0.2/24"
    echo "JOIN_IF_1=eth0"
    echo "JOIN_SSH_1=somesshnode"
  fi
  echo "DNS_TYPE=CoreDNS"
  echo "VERBOSE=false"
}

function print_usage_and_exit ()
{
	echo "Usage :"
	echo "orch template > somefile.conf"
	echo
	echo "orch.sh [up|dn] somefile.conf"
	echo
	echo "Options are the same as for provision.sh"
	echo "POD_CIDR       - CIDR for pods (defaults to 10.0.0.0/16)"
	echo "SERVICE_CIDR   - CIDR for services (defaults to 10.96.0.0/16)"
	echo "DNS_TYPE       - CoreDNS or kube-dns"
	echo "VERBOSE        - verbose"
	exit 1
}

orch_provision_cli $@
