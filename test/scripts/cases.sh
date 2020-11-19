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
source $SCRIPTDIR/cases_util.sh

# This file contains integration test scenarios. They take the form
# of kubectl commands to be run on a running cluster with CNI and
# test framework installed

function test_vpp_restart_v4 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client
	kill_local_vpp
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
	kill_local_agent
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
}

function test_vpp_restart_v6 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client
	kill_local_vpp
	test "iperf ServiceName -P4" iperf -V -c iperf-service                           -t 1 -P4 -i1
	kill_local_agent
	test "iperf ServiceName -P4" iperf -V -c iperf-service                           -t 1 -P4 -i1
}

function test_snat_ip4 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client-samehost
	configure_nodessh_ip4
	start_iperf4
	test "iperf 20.0.0.2 -P4" iperf -c 20.0.0.2                                      -t 1 -P1 -i1
	stop_iperf
	assert_test_output_contains "connected with 20.0.0.1"
}

function test_snat_ip6 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client-samehost
	configure_nodessh_ip6
	start_iperf6
	test "iperf fd11::2 -P4" iperf -V -c fd11::2                                     -t 1 -P1 -i1
	stop_iperf
	assert_test_output_contains "connected with fd11::1"
}

function test_nodeport_ip4 ()
{
	load_parameters
	NS=iperf
	SVC=iperf-service-nodeport-v4
	PROTO=TCP
	configure_nodessh_ip4
	sshtest "Nodeport v4" iperf -c $(getNodeIP node1) -p $(getServiceNodePort) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
}

function test_nodeport_ip6 ()
{
	load_parameters
	NS=iperf
	SVC=iperf-service-nodeport-v6
	PROTO=TCP
	configure_nodessh_ip6
	sshtest "Nodeport v6" iperf -V -c $(getNodeIP node1) -p $(getServiceNodePort) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
}

function test_ipv4 ()
{
	NS=iperf
	POD=iperf-client
	echo "--Cross node TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
	assert_test_output_contains_not "connect failed"

	echo "--Cross node UDP tests--"
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING

	POD=iperf-client-samehost
	echo "--Same host TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
	assert_test_output_contains_not "connect failed"

	echo "--Same host UDP tests--"
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
}

function test_ipv6 ()
{
	NS=iperf
	POD=iperf-client
	echo "--Cross node TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	test "iperf ServiceName -P4" iperf -V -c iperf-service                              -t 1 -P4 -i1

	echo "--Cross node UDP tests--"
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -V -c iperf-service                              -t 1 -P4 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING

	POD=iperf-client-samehost
	echo "--Same host tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	test "iperf ServiceName -P4" iperf -V -c iperf-service                              -t 1 -P4 -i1

	echo "--Same host UDP tests--"
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -V -c iperf-service                              -t 1 -P4 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
}

if [ $# = 0 ]; then
	echo "Usage"
	for f in $(declare -F); do
		if [[ x$(echo $f | grep -e "^test_" ) != x ]]; then
			echo "cases $(echo $f | sed s/test_//g)"
		fi
	done
else
	mkdir -p $LOG_DIR
	"test_$1"
fi
