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

function ipv4 ()
{
	start_test
	NS=iperf
	POD=iperf-client
	echo "--Cross node TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1

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
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1

	echo "--Same host UDP tests--"
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1 -u -l1450 -p5003
	assert_test_output_contains_not WARNING
}

function ipv6 ()
{
	start_test
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
	echo "cases ipv4       - run ip4 tests"
	echo "cases ipv6       - run ip6 tests"
else
	"$1"
fi
