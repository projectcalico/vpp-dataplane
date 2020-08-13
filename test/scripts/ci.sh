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

function raw_ip4 () {
	create_cluster
	start_calico
	start_test

	echo "============ RAW ipv4 ============"
	$CASES ipv4
	echo "============ VPP restart ============"
	$CASES vpp_restart_v4

	teardown_cluster
}

function ipip_ip4 () {
	create_cluster
	start_calico_ipip
	start_test

	echo "============ IPIP ipv4 ============"
	$CASES ipv4
	echo "============ VPP restart ============"
	$CASES vpp_restart_v4

	teardown_cluster
}

function ipsec_ip4 () {
	create_cluster
	start_calico_ipsec
	start_test

	echo "============ IPsec ipv4 ============"
	$CASES ipv4
	echo "============ VPP restart ============"
	$CASES vpp_restart_v4

	teardown_cluster
}

function raw_ip6 () {
	V=6 create_cluster
	start_calico
	start_test

	echo "============ RAW ipv6 ============"
	$CASES ipv6
	echo "============ VPP restart ============"
	$CASES vpp_restart_v6

	teardown_cluster
}

function ipip_ip6 () {
	V=6 create_cluster
	start_calico_ipip
	start_test

	echo "============ IPIP ipv6 ============"
	$CASES ipv6
	echo "============ VPP restart ============"
	$CASES vpp_restart_v6

	teardown_cluster
}

function ipsec_ip6 () {
	create_cluster
	start_calico_ipsec
	start_test

	echo "============ IPsec ipv6 ============"
	$CASES ipv6
	echo "============ VPP restart ============"
	$CASES vpp_restart_v6

	teardown_cluster
}

function nodeport_snat_ip4 () {
	N=0 create_cluster
	start_calico
	start_test
	start_iperf4

	echo "============ Nodeport ipv4 ============"
	$CASES snat_ip4
	stop_iperf
	assert_test_output_contains "connected with 20.0.0.1"

	echo "============ Nodeport ipv4 ============"
	NS=iperf
	SVC=iperf-service-nodeport-v4
	PROTO=TCP
	sshtest "Nodeport v4" iperf -c $(getNodeIP node1) -p $(getServiceNodePort) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"

	teardown_cluster
}

function nodeport_snat_ip6 () {
	V=6 N=0 create_cluster
	start_calico
	start_test
	start_iperf6

	echo "============ Nodeport ipv6 ============"
	$CASES snat_ip6
	stop_iperf
	assert_test_output_contains "connected with fd11::1"

	echo "============ Nodeport ipv6 ============"
	NS=iperf
	SVC=iperf-service-nodeport-v6
	PROTO=TCP
	sshtest "Nodeport v6" iperf -V -c $(getNodeIP node1) -p $(getServiceNodePort) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"

	teardown_cluster
}

if [ $# = 0 ]; then
	echo "Usage"
	echo "ci raw_ip4"
	echo "ci ipip_ip4"
	echo "ci ipsec_ip4"
	echo "ci raw_ip6"
	echo "ci ipip_ip6"
	echo "ci ipsec_ip6"
	echo "ci nodeport_snat_ip4"
	echo "ci nodeport_snat_ip6"
else
	load_parameters
	"$1"
fi
