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

LOGFILE=testrun.log
LAST_TEST_LOGFILE=testrun.log~

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

function onePodIP () {
	N=$(getPodIP | wc -l)
	if [ x$N != x0 ]; then
	  getPodIP | head -n $((1 + RANDOM % $N)) | tail -n 1
	fi
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
	PRESENT=$( cat $LAST_TEST_LOGFILE | grep ${1} | wc -l)
	if [ x$PRESENT = x0 ]; then
	  green "Assert OK (doesn't contain $1)"
	else
	  red "Assert FAILED (contains $1)"
	fi
}

function assert_test_output_contains () {
	PRESENT=$(cat $LAST_TEST_LOGFILE | grep ${1} | wc -l)
	if [ x$PRESENT = x0 ]; then
	  red "Assert FAILED (doesn't contain $1)"
	else
	  green "Assert OK (contains $1)"
	fi
}

function wait_for_calico_test () {
	NPODS=0
	sleep 1
	while [ x$NPODS != x1 ]; do
	  NPODS=$(kubectl -n $SVC get pods | grep -v Running | wc -l)
	  echo "test not yet ready..."
	  sleep 1
	done
}

function wait_for_calico_vpp () {
	NVPPS=0
	while [ x$NVPPS != x2 ]; do
	  NVPPS=$(kubectl -n kube-system get pods | grep calico-vpp | grep '2/2' | wc -l)
	  echo "calico not yet ready"
	  sleep 2
	done
}

function wait_for_coredns () {
	NVPPS=0
	while [ x$NVPPS != x2 ]; do
	  NVPPS=$(kubectl -n kube-system get pods | grep coredns | grep '1/1' | wc -l)
	  echo "coredns not yet ready..."
	  sleep 2
	done
}

function start_test () {
	echo "Starting test clients... at $(date)"
	$SCRIPTDIR/test.sh up iperf > iperfup.log 2>&1
	wait_for_coredns
	SVC=iperf wait_for_calico_test
}


