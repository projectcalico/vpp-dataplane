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
source $SCRIPTDIR/shared.sh

function k () {
	kubectl -n $NS $@
}

function kex () {
	echo "Running $@"
	k exec -it $POD -- timeout -k 1 4 $@
}

function getClusterIP () {
	k get service/$SVC -o json | jq -r .spec.clusterIP
}

function getPodIPs () {
	k get pods -o json | jq -r '.items[] | .status.podIP,.metadata.name' | xargs -n 2 echo
}

function getPodIP () {
	getPodIPs | grep $POD | cut -d ' ' -f 1
}

function getNodeIP () {
	kubectl get nodes $1 -o go-template --template='{{range .status.addresses}}{{printf "%s\n" .address}}{{end}}' | head -1
}

function getServiceIP () {
	kubectl -n $NS get service $SVC -o go-template --template='{{printf "%s\n" .spec.clusterIP}}'
}

function getServiceNodePort () {
	kubectl -n $NS get service $SVC -o go-template --template='{{range .spec.ports}}{{printf "%d %s\n" .nodePort .protocol}}{{end}}' | grep $PROTO | awk '{print $1}'
}

function onePodIP () {
	N=$(getPodIP | wc -l)
	if [ x$N != x0 ]; then
	  getPodIP | head -n $((1 + $RANDOM % $N)) | tail -n 1
	fi
}

function getVppPid () {
	ps aux | grep -v grep | grep "vpp -c" | tail -n 1 | awk '{print $2}'
}

function kill_local_vpp () {
	vpp_pid=$(getVppPid)
	blue "Kill vpp [${vpp_pid}], waiting 30 seconds for restart..."
	sudo kill $vpp_pid
	sleep 30
}

function test () {
	echo "-----------TESTCASE $1-----------" > $LAST_TEST_LOGFILE
	kex ${@:2} >> $LAST_TEST_LOGFILE
	CODE=$?
	if [ x$CODE = x0 ]; then
	  green "$1 .... OK"
	else
	  red "$1 .... FAILED exit=$CODE"
	fi
	cat $LAST_TEST_LOGFILE >> $LOGFILE
}

function assert_test_output_contains_not () {
	PRESENT=$( cat $LAST_TEST_LOGFILE | grep "${1}" | wc -l)
	if [ x$PRESENT = x0 ]; then
	  green "Assert OK (doesn't contain '$1')"
	else
	  red "Assert FAILED (contains '$1')"
	fi
}

function assert_test_output_contains () {
	PRESENT=$(cat $LAST_TEST_LOGFILE | grep "${1}" | wc -l)
	if [ x$PRESENT = x0 ]; then
	  red "Assert FAILED (doesn't contain '$1')"
	else
	  green "Assert OK (contains '$1')"
	fi
}

function configure_nodessh_ip4 () {
	ssh $NODESSH -t "$PCI_BIND_NIC_TO_KERNEL"
	ssh $NODESSH -t "sudo ip link set $IF up" > /dev/null 2>&1
	ssh $NODESSH -t "sudo ip addr add 20.0.0.2/24 dev $IF" > /dev/null 2>&1 || true
}

function configure_nodessh_ip6 () {
	ssh $NODESSH -t "$PCI_BIND_NIC_TO_KERNEL"
	ssh $NODESSH -t "sudo ip link set $IF up" > /dev/null 2>&1
	ssh $NODESSH -t "sudo ip addr add fd11::2/120 dev $IF" > /dev/null 2>&1 || true
}

function start_iperf4 () {
	ssh $NODESSH -t "nohup bash -c 'iperf -s -B 20.0.0.2 > /tmp/iperf.log 2>&1 &'" > /dev/null 2>&1
}

function start_iperf6 () {
	ssh $NODESSH -t "nohup bash -c 'iperf -s -V -B fd11::2 > /tmp/iperf.log 2>&1 &'" > /dev/null 2>&1
}

function stop_iperf () {
	ssh $NODESSH -t "sudo pkill iperf ; cat /tmp/iperf.log" > $LAST_TEST_LOGFILE 2> /dev/null
}

function sshtest () {
	echo "-----------TESTCASE $1-----------" > $LAST_TEST_LOGFILE
	ssh $NODESSH -t "timeout -k 1 4 ${@:2}" >> $LAST_TEST_LOGFILE
	CODE=$?
	if [ x$CODE = x0 ]; then
	  green "$1 .... OK"
	else
	  red "$1 .... FAILED exit=$CODE"
	fi
	cat $LAST_TEST_LOGFILE >> $LOGFILE
}

