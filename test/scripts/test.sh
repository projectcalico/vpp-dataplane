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
VPP_DATAPLANE_DIRECTORY="$(cd $SCRIPTDIR/../.. >/dev/null 2>&1 && pwd)"

PERFTESTDIR=/path/to/perf-tests # git clone git@github.com:kubernetes/perf-tests.git

N_TESTS=${N_TESTS:=3}
TEST_LEN=${TEST_LEN:=30}
# Skip N sec at start at end
TEST_SKIP=${TEST_SKIP:=10}
CASE=${CASE:=IPERF}
VPP_STATS=${VPP_STATS:=n}

k_delete_namespace ()
{
  NAMESPACE_COUNT=$(kubectl get namespace $1 2> /dev/null | wc -l)
  if [ x$NAMESPACE_COUNT = x0 ]; then
	  echo "namespace $1 doesnt exist"
  else
	  kubectl delete namespace $1
  fi
}

k_create_namespace ()
{
  NAMESPACE_COUNT=$(kubectl get namespace $1 2> /dev/null | wc -l)
  if [ x$NAMESPACE_COUNT = x0 ]; then
	  kubectl create namespace $1
  else
	  echo "namespace $1 already exists"
  fi
}

metallb_test ()
{
	kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/namespace.yaml
	kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/metallb.yaml
	kubectl delete ds speaker -n metallb-system
	kubectl apply -f $SCRIPTDIR/../yaml/metallb/test_metallb.yaml
}

metallb_test_delete ()
{
	kubectl delete -f $SCRIPTDIR/../yaml/metallb/test_metallb.yaml
	kubectl delete -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/namespace.yaml
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
  NAME=$1
  if [ x$2 != x ]; then
	YAML_FILE=$SCRIPTDIR/../yaml/$NAME/test_$2.yaml
  else
	YAML_FILE=$SCRIPTDIR/../yaml/$NAME/test.yaml
  fi
  shift
  if [ ! -f ${YAML_FILE} ]; then
  	echo "${YAML_FILE} doesnt exist"
  	exit 1
  fi

  get_nodes
  k_create_namespace $NAME

  export VPP_DATAPLANE_DIRECTORY=$VPP_DATAPLANE_DIRECTORY
  cat $YAML_FILE | \
	envsubst | \
	kubectl apply -f -
}

test_delete ()
{
  NAME=$1
  if [ x$2 != x ]; then
	YAML_FILE=$SCRIPTDIR/../yaml/$NAME/test_$2.yaml
  else
	YAML_FILE=$SCRIPTDIR/../yaml/$NAME/test.yaml
  fi

  if [ ! -f ${YAML_FILE} ]; then
  	echo "${YAML_FILE} doesnt exist"
  	exit 1
  fi
  cat $YAML_FILE | \
	kubectl delete -f -
  k_delete_namespace $1
}

function print_usage_and_exit ()
{
    echo "Usage:"
    echo "test.sh up   [perf|npperf|perf3|wrk|nginx|monit|scalepods]     - Create test yaml and apply it"
    echo "test.sh down [perf|npperf|perf3|wrk|nginx|monit|scalepods]     - Delete test yaml"
    echo
    echo "test.sh build nptest"
    echo "test.sh pin CPUS=27-35,39-47                                   - pin nginx/iperf/vhost to given CPUS"
    echo "test.sh run [DIR] [N_TESTS=3] [TEST_SZ=4096|2MB] [CASE=WRK1|WRK2|IPERF]"
    echo "            [N_FLOWS=4] [CPUS=27-35,39-47] [OTHERHOST=sshname]"
    echo "            [TEST_LEN=30] [TEST_SKIP=10] [VPP_STATS=n]"
    echo "test.sh report [DIR]"
    echo
    exit 0
}

function test_pin ()
{
	while (( "$#" )) ; do
      eval $1
      shift
	done
	if [ x$CPUS = x ]; then
		echo "provide CPUS=27-35,39-47"
		exit 1
	fi
	ps aux|grep -v awk|awk '/vhost/{print $2}'|while read p;do sudo taskset -pc ${CPUS} $p;done
	ps aux|grep -v awk|awk '/iperf/{print $2}'|while read p;do sudo taskset -pc ${CPUS} $p;done
	ps aux|grep -v awk|awk '/nginx/{print $2}'|while read p;do sudo taskset -pc ${CPUS} $p;done
}

kube_test_cli ()
{
  if [[ "$1 $2" = "up nptest" ]]; then
    calico_up_nptest
  elif [[ "$1 $2" = "down nptest" ]]; then
	calico_down_nptest
  elif [[ "$1 $2" = "build nptest" ]]; then
    calico_build_nptest
  elif [[ "$1" = "metallb" ]]; then
    metallb_test
  elif [[ "$1" = "metallb_delete" ]]; then
    metallb_test_delete
  elif [[ "$1" = "up" ]]; then
	shift ; test_apply $@
  elif [[ "$1" = "run" ]]; then
	shift ; test_run $@
  elif [[ "$1" = "pin" ]]; then
	shift ; test_pin $@
  elif [[ "$1" = "report" ]]; then
	shift ; test_report $@
  elif [[ "$1" = "down" ]]; then
	shift ; test_delete $@
  else
  	print_usage_and_exit
  fi
}

setup_test_class_WRK1 () { return; }
setup_test_WRK1 ()
{
	if [ x$OTHERHOST = x ]; then
		echo "Please provide OTHERHOST=sshname"
		exit 1
	fi

	scp $OTHERHOST:${TMP}/calico-vpp.yaml $DIR/cni.yaml
	CLUSTER_IP=$( kubectl get svc -n nginx nginx-service-${TEST_N} -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	ssh $OTHERHOST "sudo conntrack -F"
	while (( "$(netstat -tn4 | grep $CLUSTER_IP:80 | wc -l)" )); do
		echo "Waiting for connection cleanup"
		sleep 1
	done
}

setup_test_class_WRK2 () { return; }
setup_test_WRK2 ()
{
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
	sudo conntrack -F

	while (( "$( $SCRIPTDIR/vppdev.sh vppctl node2 sh cnat session | grep "active elements" | awk '{print $1}' )" > 50 )); do
		echo "Waiting for connection cleanup"
		sleep 1
	done
}

setup_test_class_IPERF () { return; }
setup_test_IPERF ()
{
	N_FLOWS=${N_FLOWS:=4}
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
}

run_test_IPERF ()
{
	CLUSTER_IP=$( kubectl get svc -n iperf iperf-service -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	TEST_CMD="taskset -c ${CPUS} iperf -c ${CLUSTER_IP} -P${N_FLOWS} -t${TEST_LEN} -i1"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	kubectl exec -it iperf-client -n iperf -- $TEST_CMD > $DIR/test_output
}

setup_test_class_IPERF3 () { return; }
setup_test_IPERF3 ()
{
	N_FLOWS=${N_FLOWS:=4}
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
}

run_test_IPERF3 ()
{
	CLUSTER_IP=$( kubectl get svc -n iperf3 iperf3-service -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	TEST_CMD="taskset -c ${CPUS} iperf3 -c ${CLUSTER_IP} -P${N_FLOWS} -t${TEST_LEN} -i1"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	kubectl exec -it iperf3-client -n iperf3 -- $TEST_CMD > $DIR/test_output
}

setup_test_class_IPERF3_VCL () { return; }
setup_test_IPERF3_VCL ()
{
	N_FLOWS=${N_FLOWS:=4}
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
}

run_test_IPERF3_VCL ()
{
	CLUSTER_IP=$( kubectl get svc -n iperf3-vcl iperf3-service -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	TEST_CMD="taskset -c ${CPUS} iperf3-vcl -c ${CLUSTER_IP} -P${N_FLOWS} -t${TEST_LEN} -i1"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	kubectl exec -it iperf3-client -n iperf3-vcl -- $TEST_CMD > $DIR/test_output
}

setup_test_class_IPERF3_VCL_TLS () { return; }
setup_test_IPERF3_VCL_TLS ()
{
	N_FLOWS=${N_FLOWS:=4}
	TLS_ENGINE=${TLS_ENGINE:=4}
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
}

set +x
run_test_IPERF3_VCL_TLS ()
{
	POD_IP=$( kubectl get pods -n iperf3-vcl -o wide | grep server | awk '{print $6}' )
	TEST_CMD="taskset -c ${CPUS} env TLS_ENGINE=${TLS_ENGINE} iperf3-tls-vcl -c ${POD_IP} -P${N_FLOWS} -t${TEST_LEN} -i1"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	kubectl exec -it iperf3-client -n iperf3-vcl -- $TEST_CMD > $DIR/test_output
}

setup_test_class_MEMIF () { return; }
setup_test_MEMIF ()
{
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
	$SCRIPTDIR/vppdev.sh vppctl node1 cnat session purge
}

mvpp_vppctl ()
{
	kubectl exec -i -n mvpp mvpp -- /home/hostuser/vppctl.sh $@ > $DIR/test_output
}

# this test assumes
# - we have mvpp up & running (launched by user), and attached to the memif
# - We have trex cloned in ~/trex-core on ${OTHERHOST} and trex is running
# - We have vpp-dataplane cloned on ${OTHERHOST} in the same directory as here
run_test_MEMIF ()
{
	if [ x$ISVIP = xyes ]; then
		DST_IP=$( kubectl get svc -n mvpp mvpp-service -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	else
		DST_IP=$( kubectl get pods -n mvpp -o wide | grep mvpp | awk '{print $6}' )
	fi
	TEST_CMD="$SCRIPTDIR/trex_udp_gen.py --ip ${DST_IP} --frame-size ${FRAME_SIZE} -m 100% -d ${TEST_LEN} --limit-flows ${LIMIT_FLOWS}"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	mvpp_vppctl monitor interface memif1/0 interval 1 count ${TEST_LEN} &
	MVPPPID=$?
	PYTHONPATH='~/trex-core/scripts/automation/trex_control_plane/interactive'
	ssh -t $OTHERHOST PYTHONPATH=$PYTHONPATH $TEST_CMD > $DIR/trex_output
	echo "waiting..."
	wait $MYVPPPID
}

run_test_WRK1 ()
{
	TEST_SZ=${TEST_SZ:=4096} # 4096 // 2MB
	CLUSTER_IP=$( kubectl get svc -n nginx nginx-service-1 -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	TEST_CMD="sudo prlimit --nofile=100000 numactl -m 1 -C ${CPUS} ./wrk.py -t10 -c1000 -d${TEST_LEN}s --latency http://${CLUSTER_IP}/${TEST_SZ}"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	$TEST_CMD > $DIR/test_output
}

setup_test_ENVOY ()
{
	cp ${TMP}/calico-vpp.yaml $DIR/cni.yaml
	if [ x$ISVPP = xyes ]; then
		$SCRIPTDIR/vppdev.sh vppctl node1 cnat session purge
	else
		sudo conntrack -F
	fi
}

run_envoy_linux ()
{
	kubectl exec -n envoy envoy-linux -- taskset -c ${CPUS} \
	  envoy -c /etc/envoy/envoy.yaml \
	  --concurrency ${N_ENVOYS} > $USER_DIR/envoy_output 2>&1
}

run_envoy_vcl ()
{
	kubectl exec -n envoy envoy-vcl -- taskset -c ${CPUS} \
	  envoy -c /etc/envoy/envoyvcl.yaml \
	  --concurrency ${N_ENVOYS} > $USER_DIR/envoy_output 2>&1
}

setup_test_class_ENVOY ()
{
	sudo pkill envoy
	if [ x$ISVCL = xyes ]; then
		$SCRIPTDIR/vppdev.sh vppctl node1 set cnat snat-policy prefix 20.0.0.2/32
		run_envoy_vcl &
	else
		run_envoy_linux &
	fi
}

run_test_ENVOY ()
{
	if [ x$ISVCL = xyes ]; then
		DST_IP=$( kubectl get pods -n envoy -o wide | grep envoy-vcl | awk '{print $6}' )
	else
		DST_IP=$( kubectl get pods -n envoy -o wide | grep envoy-linux | awk '{print $6}' )
	fi
	TEST_CMD="$HOME/wrk/wrk.py taskset -c 0-42 wrk -c300 -t30 -d${TEST_LEN}s http://${DST_IP}:10001/64B.json"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	ssh -t $OTHERHOST $TEST_CMD > $DIR/test_output
}

run_test_WRK2 ()
{
	TEST_SZ=${TEST_SZ:=4096} # 4096 // 2MB
	CLUSTER_IP=$( kubectl get svc -n nginx nginx-service-1 -o go-template --template='{{printf "%s\n" .spec.clusterIP}}' )
	TEST_CMD="/wrk/wrk.py -t10 -c1000 -d${TEST_LEN}s --latency http://${CLUSTER_IP}/${TEST_SZ}"
	echo "Running test : ${TEST_CMD}"
	echo $TEST_CMD > $DIR/test_command.sh
	kubectl exec -it wrk-client -n wrk -- $TEST_CMD > $DIR/test_output
}

test_run_one ()
{
	mkdir -p $DIR
	setup_test_$CASE
	if [ "$VPP_STATS" = "y" ]; then
		$SCRIPTDIR/vppdev.sh clear
		$SCRIPTDIR/vppdev.sh export $DIR start
	fi
	echo $CASE > $DIR/testcase

	start_time=$(date "+%s")
	# Run actual test
	run_test_$CASE
	end_time=$(date "+%s")

	for node in $(kubectl get nodes -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}')
	do
		SVC=monit C=monit POD=monit NODE=$node exec_node /stats.sh ${start_time} ${end_time} > $DIR/cpu_mem_usage.${node}
	done
	echo "start=${start_time} end=${end_time}" > $DIR/timestamps

	if [ "$VPP_STATS" = "y" ]; then
		$SCRIPTDIR/vppdev.sh export $DIR end
	fi
}

test_run ()
{
	USER_DIR=$1
	shift
	while (( "$#" )) ; do
      eval $1
      shift
	done

	if [ x$CPUS = x ] && [ x$CASE != xMEMIF ]; then
		echo "provide CPUS=27-35,39-47"
		exit 1
	fi

	if [ x$CASE = xWRK1 ]; then
		if [ x$OTHERHOST = x ]; then
			echo "Please provide OTHERHOST=sshname"
			exit 1
		fi
		mkdir -p ~/.kube && scp $OTHERHOST:~/.kube/config ~/.kube/config
	fi
	if [ x$USER_DIR = x ]; then
		echo "Please provide a directory"
		exit 1
	fi
	if [ -d "$USER_DIR" ]; then
		echo "directory $USER_DIR exists"
		exit 1
	fi

	mkdir -p $USER_DIR
	setup_test_class_$CASE
	for i in $(seq $N_TESTS); do
		echo "Test run #${i}"
		TEST_N=$i DIR=$USER_DIR/test_${i} test_run_one
	done
}

get_avg_cpu ()
{
	# cpu-user;cpu-nice;cpu-system;cpu-iowait;cpu-steal;memory-used;records-number
	NODE=$2
	FILE=$1/cpu_mem_usage.${NODE}
	if [ ! -f "${FILE}" ]; then
		printf ";;;;;;"
	else
		tail -n +2 $FILE | \
    	tail -n +${TEST_SKIP} | \
    	head -n +${TEST_SKIP} | \
		awk '{M+=$6;U+=$1;N+=$2;S+=$3;I+=$4;T+=$5;}
			END {
				printf "%.2f;%.2f;%.2f;%.2f;%.2f;%d;%d",U/NR,N/NR,S/NR,I/NR,T/NR,M/NR,NR
			}'
	fi
}

get_wrk_csv_output ()
{
  FILE=$1/test_output
  tail -1 $FILE | sed 's/[^[:print:]]//g'
}

get_mvpp_csv_output ()
{
  FILE=$1/test_output
  cat $FILE | \
    tail -n +${TEST_SKIP} | \
    head -n +${TEST_SKIP} | \
    awk '{print $2}' | \
    sed s/Mpps//g | \
    awk '{BPS+=$1}
    	END {
    		printf "%.2f", BPS/NR
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
    tail -n +${TEST_SKIP} | \
    head -n +${TEST_SKIP} | \
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
  if [ ! -f $DIR/testcase ]; then
  	echo "testcase undefined"
  	exit 1
  fi
  CASE=$(cat $DIR/testcase)
  if [ x$CASE = xIPERF ] || [ x$CASE = xIPERF3 ] || [ x$CASE = xIPERF3_VCL ] || [ x$CASE = xIPERF3_VCL_TLS ]; then
	echo "$TEST_N;$(get_avg_iperf_bps $DIR);$(get_avg_cpu $DIR node1);$(get_avg_cpu $DIR node2)"
  elif [ x$CASE = xWRK ] || [ x$CASE = xWRK2 ]; then
 	echo "$TEST_N;$(get_wrk_csv_output $DIR);$(get_avg_cpu $DIR node1);$(get_avg_cpu $DIR node2)"
  elif [ x$CASE = xENVOY ]; then
 	echo "$TEST_N;$(get_wrk_csv_output $DIR);$(get_avg_cpu $DIR node1)"
  elif [ x$CASE = xMEMIF ]; then
 	echo "$TEST_N;$(get_mvpp_csv_output $DIR);$(get_avg_cpu $DIR node1)"
  else
    echo "Unknown case"
  fi
}

test_report ()
{
	USER_DIR=$1
	if [ x$USER_DIR = x ]; then
		echo "Please provide a directory"
		exit 1
	fi
	if [ ! -d $USER_DIR ]; then
		echo "$USER_DIR doesn't exist"
		exit 1
	fi
	N_TESTS=$(ls -d ./$USER_DIR/test_* | wc -l)
	for i in $(seq $N_TESTS); do
		get_avg_report $USER_DIR $i
	done
}

kube_test_cli $@
