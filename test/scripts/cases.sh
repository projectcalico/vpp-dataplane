#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $SCRIPTDIR/cases_util.sh

function run_ip4_iperf_tests ()
{
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

function run_ip6_iperf_tests ()
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


function raw_ip4 () {
	create_cluster calicovpp/v4_flat_dpdk_0w.sh
	start_calico calicovpp/v4_flat_dpdk_0w.sh
	start_test

	echo "============ RAW ipv4 ============"
	run_ip4_iperf_tests
	teardown_cluster
}

function ipip_ip4 () {
	create_cluster calicovpp/v4_ipip_dpdk_0w.sh
	start_calico calicovpp/v4_ipip_dpdk_0w.sh
	start_test

	echo "============ IPIP ipv4 ============"
	run_ip4_iperf_tests
	teardown_cluster
}

function ipsec_ip4 () {
	create_cluster calicovpp/v4_ipsec_dpdk_0w.sh
	start_calico calicovpp/v4_ipsec_dpdk_0w.sh
	start_test

	echo "============ IPsec ipv4 ============"
	run_ip4_iperf_tests
	teardown_cluster
}

function raw_ip6 () {
	create_cluster calicovpp/v6_flat_dpdk_0w.sh
	start_calico calicovpp/v6_flat_dpdk_0w.sh
	start_test

	echo "============ RAW ipv6 ============"
	run_ip6_iperf_tests
	teardown_cluster
}

function full () {
	raw_ip4
	raw_ip6
	ipip_ip4
	ipsec_ip4
}

if [ $# = 0 ]; then
	echo "Usage"
	echo "cases full       - run all tests"
	echo "cases [casename] - run one test"
else
	"$1"
fi
