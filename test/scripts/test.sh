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

PERFTESTDIR=/path/to/perf-tests # git clone git@github.com:kubernetes/perf-tests.git

k_delete_namespace ()
{
  TMP=$(kubectl get namespace $1 2> /dev/null | wc -l)
  if [ x$TMP = x0 ]; then
	  echo "namespace $1 doesnt exist"
  else
	  kubectl delete namespace $1
  fi
}

k_create_namespace ()
{
  TMP=$(kubectl get namespace $1 2> /dev/null | wc -l)
  if [ x$TMP = x0 ]; then
	  kubectl create namespace $1
  else
	  echo "namespace $1 already exists"
  fi
}

calico_up_nptest ()
{
  kubectl config set-context --current --namespace=netperf
  cd $PERFTESTDIR/network/benchmarks/netperf
  ./launch -kubeConfig ~/.kube/config -image calicovpp/nptest -pull-policy IfNotPresent
}

calico_down_nptest ()
{
  k_delete_namespace netperf
  kubectl config set-context --current --namespace=kube-system
}

calico_build_nptest ()
{
  cd $PERFTESTDIR/network/benchmarks/netperf
  make docker DOCKERREPO=calicovpp/nptest
}

get_nodes ()
{
  NODES=($(kubectl get nodes -o jsonpath="{.items[*].metadata.name}"))
  if [ ${#NODES[@]} -lt 1 ]; then
    echo "No nodes found in the cluster, cannot run test"
    exit 1
  elif [ ${#NODES[@]} -lt 2 ]; then
    echo "Warning: only 1 node found, remote tests will be meaningless"
    NODES[1]=${NODES[0]}
  fi
  echo "Using nodes: ${NODES[0]} ${NODES[1]}"
}

test_apply ()
{
  if [ -z "$2" ]; then
    yaml_file="test.yaml"
  else
    yaml_file=$2
  fi

  if [ ! -d $SCRIPTDIR/perftest/$1 ]; then
  	cd $SCRIPTDIR/perftest
  	echo "Please specify a config yaml in $(ls -d */)"
  	exit 1
  fi
  get_nodes
  k_create_namespace $1
  sed -e "s/_NODE_1_/${NODES[0]}/" -e "s/_NODE_2_/${NODES[1]}/" $SCRIPTDIR/perftest/$1/$yaml_file | kubectl apply -f -
}

test_delete ()
{
  if [ -z "$2" ]; then
    yaml_file="test.yaml"
  else
    yaml_file=$2
  fi

  if [ ! -d $SCRIPTDIR/perftest/$1 ]; then
  	cd $SCRIPTDIR/perftest
  	echo "Please specify a config yaml in $(ls -d */)"
  	exit 1
  fi
  kubectl delete -f $SCRIPTDIR/perftest/$1/$yaml_file
  echo $yaml_file
  k_delete_namespace $1
}

test_run_one ()
{
	mkdir -p $DIR
	cp /tmp/calico-vpp.yaml $DIR/cni.yaml
	$SCRIPTDIR/vppdev.sh clear
	$SCRIPTDIR/vppdev.sh export $DIR start
	TEST_CMD="iperf -c iperf-service -P4 -t10 -i1"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh

	start_time=$(date "+%s")
	# Run actual test
	kubectl exec -it iperf-client -n iperf -- $TEST_CMD > $DIR/test_output
	end_time=$(date "+%s")

	for node in $(kubectl get nodes -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}')
	do
		SVC=monit C=monit POD=monit NODE=$node exec_node /stats.sh ${start_time} ${end_time} > $DIR/cpu_mem_usage
	done
	echo "start=${start_time} end=${end_time}" > $DIR/timestamps

	$SCRIPTDIR/vppdev.sh export $DIR end
}

test_run ()
{
	USER_DIR=$1
	N_TESTS=${N_TESTS:=3}
	if [ x$USER_DIR = x ]; then
		echo "Please provide a directory"
		exit 1
	fi
	if [ -d "$USER_DIR" ]; then
		echo "directory $USER_DIR exists"
		exit 1
	fi

	for i in $(seq $N_TESTS); do
		echo "Test run #${i}"
		DIR=$USER_DIR/test_${i} test_run_one
	done
}

function print_usage_and_exit ()
{
    echo "Usage:"
    echo "test.sh up   [perf|npperf|perf3|wrk|nginx]     - Create test yaml and apply it"
    echo "test.sh down [perf|npperf|perf3|wrk|nginx]     - Delete test yaml"
    echo
    echo "test.sh build nptest"
    echo "test.sh run [DIR]"
    echo
    exit 0
}

kube_test_cli ()
{
  if [[ "$1 $2" = "up nptest" ]]; then
    calico_up_nptest
  elif [[ "$1 $2" = "down nptest" ]]; then
	calico_down_nptest
  elif [[ "$1 $2" = "build nptest" ]]; then
    calico_build_nptest
  elif [[ "$1" = "up" ]]; then
	shift ; test_apply $@
  elif [[ "$1" = "run" ]]; then
	shift ; test_run $@
  elif [[ "$1" = "report" ]]; then
	shift ; test_report $@
  elif [[ "$1" = "down" ]]; then
	shift ; test_delete $@
  else
  	print_usage_and_exit
  fi
}

get_avg_cpu ()
{
	FILE=$1/cpu_mem_usage
	tail -n +2 $FILE | awk '{M+=$6;U+=$1;N+=$2;S+=$3;I+=$4;T+=$5;}
		END {
			printf "%.2f;%.2f;%.2f;%.2f;%.2f;%d;%d",U/NR,N/NR,S/NR,I/NR,T/NR,M/NR,NR
		}'
}

get_avg_iperf_bps ()
{
  FILE=$1/test_output
  if [[ x$(cat $FILE | grep '\[SUM\]') = x ]]; then
    spattern="sec"
  else
    spattern='\[SUM\]'
  fi
  cat $FILE | grep $spattern | \
    egrep -o "[0-9\.]+ [MKG]bits/s" | \
    sed "s@ Gbits/s@ 1000000000@g" | \
    sed "s@ Mbits/s@ 1000000@g" | \
    sed "s@ Kbits/s@ 1000@g" | \
    awk '{BPS+=$1}
    	END {
    		printf "%.2f", BPS/NR
    	}'
}

get_avg_report ()
{
  TEST_N=$2
  DIR=$1/test_${TEST_N}
  echo "$TEST_N;$(get_avg_iperf_bps $DIR);$(get_avg_cpu $DIR)"
}

test_report ()
{
	USER_DIR=$1
	N_TESTS=${N_TESTS:=3}
	if [ x$USER_DIR = x ]; then
		echo "Please provide a directory"
		exit 1
	fi
	echo "test;Gbps;cpu-user;cpu-nice;cpu-system;cpu-iowait;cpu-steal;memory-used;records-number";
	for i in $(seq $N_TESTS); do
		get_avg_report $USER_DIR $i
	done
}

kube_test_cli $@
