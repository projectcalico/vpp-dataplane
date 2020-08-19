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
source $SCRIPTDIR/ci_util.sh
source $SCRIPTDIR/cases_util.sh

# This file contains full integration tests. It provisions a cluster,
# deploys calico-vpp CNI to it, applies the test framework yaml and
# run the test scenarios contained in cases.sh

function test_raw_ip4 () {
	create_cluster
	start_calico
	start_test

	echo "============ RAW ipv4 ============"
	$CASES ipv4
	echo "============ VPP restart ============"
	$CASES vpp_restart_v4

	teardown_cluster
}

function test_ipip_ip4 () {
	create_cluster
	start_calico_ipip
	start_test

	echo "============ IPIP ipv4 ============"
	$CASES ipv4
	echo "============ VPP restart ============"
	$CASES vpp_restart_v4

	teardown_cluster
}

function test_ipsec_ip4 () {
	create_cluster
	start_calico_ipsec
	start_test

	echo "============ IPsec ipv4 ============"
	$CASES ipv4
	echo "============ VPP restart ============"
	$CASES vpp_restart_v4

	teardown_cluster
}

function test_raw_ip6 () {
	V=6 create_cluster
	start_calico
	start_test

	echo "============ RAW ipv6 ============"
	$CASES ipv6
	echo "============ VPP restart ============"
	$CASES vpp_restart_v6

	teardown_cluster
}

function test_ipip_ip6 () {
	V=6 create_cluster
	start_calico_ipip
	start_test

	echo "============ IPIP ipv6 ============"
	$CASES ipv6
	echo "============ VPP restart ============"
	$CASES vpp_restart_v6

	teardown_cluster
}

function test_ipsec_ip6 () {
	create_cluster
	start_calico_ipsec
	start_test

	echo "============ IPsec ipv6 ============"
	$CASES ipv6
	echo "============ VPP restart ============"
	$CASES vpp_restart_v6

	teardown_cluster
}

function test_nodeport_snat_ip4 () {
	N=1 create_cluster
	N=1 start_calico
	N=1 start_test

	echo "============ Natoutgoing ipv4 ============"
	$CASES snat_ip4

	echo "============ Nodeport ipv4 ============"
	$CASES nodeport_ip4

	teardown_cluster
}

function test_nodeport_snat_ip6 () {
	V=6 N=1 create_cluster
	N=1 start_calico
	N=1 start_test

	echo "============ Natoutgoing ipv6 ============"
	$CASES snat_ip6

	echo "============ Nodeport ipv6 ============"
	$CASES nodeport_ip6

	teardown_cluster
}

if [ $# = 0 ]; then
	echo "Usage"
	for f in $(declare -F); do
		if [[ x$(echo $f | grep -e "^test_" ) != x ]]; then
			echo "ci $(echo $f | sed s/test_//g)"
		fi
	done
else
	check_no_running_kubelet
	load_parameters
	"test_$1"
fi
