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
  echo "$SCRIPTDIR/provision.sh $1 IF=$IF NODE_IP=$2 MASTER_NODE_IP=$3 POD_CIDR=$POD_CIDR SERVICE_CIDR=$SERVICE_CIDR DNS_TYPE=$DNS_TYPE AVF=$AVF VERBOSE=$VERBOSE NODE_NAME=$NODE_NAME"
}

function create_k8_cluster () {
	N=1
	NODE_NAME=node$N
	eval $(provision up $MASTER "")
	for i in $(echo $SLAVES | sed 's/,/ /g' ) ; do
		ip=${i%%/*}
		NODE_IP=${i%%@*}
		SSH_NAME=${i##*@}
		N=$((N+1))
		NODE_NAME=node$N
		ssh $SSH_NAME -t $(provision up $NODE_IP ${MASTER%%/*})
	done
}

function destroy_k8_cluster ()
{
	for i in $(echo $SLAVES | sed 's/,/ /g' ) ; do
		SSH_NAME=${i##*@}
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
		create_k8_cluster
	else
		destroy_k8_cluster
	fi

}

function print_usage_and_exit ()
{
	echo "Usage :"
	echo "orch.sh [up|dn] [OPTIONS]"
	echo
	echo "orch.sh up IF=eth0 MASTER=20.0.0.1/24 SLAVES=20.0.0.2/24@vq2"
	echo
	echo "Options are the same as for provision.sh"
	echo "IF             - linux if name to use"
	echo "POD_CIDR       - CIDR for pods (defaults to 10.0.0.0/16)"
	echo "SERVICE_CIDR   - CIDR for services (defaults to 10.96.0.0/16)"
	echo "DNS_TYPE       - CoreDNS or kube-dns"
	echo "AVF            - if 'yes' Create a VF for vpp's avf driver"
	echo "VERBOSE        - verbose"
	exit 1
}

orch_provision_cli $@
