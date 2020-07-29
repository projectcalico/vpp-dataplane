#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $SCRIPTDIR/shared.sh
# source $SCRIPTDIR/conf/calico

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

test_apply ()
{
  if [ ! -d $SCRIPTDIR/perftest/$1 ]; then
  	cd $SCRIPTDIR/perftest
  	echo "Please specify a config yaml in $(ls -d */)"
  	exit 1
  fi
  k_create_namespace $1
  kubectl apply -f $SCRIPTDIR/perftest/$1/test.yaml
}

test_delete ()
{
  if [ ! -d $SCRIPTDIR/perftest/$1 ]; then
  	cd $SCRIPTDIR/perftest
  	echo "Please specify a config yaml in $(ls -d */)"
  	exit 1
  fi
  kubectl delete -f $SCRIPTDIR/perftest/$1/test.yaml
  k_delete_namespace $1
}

function print_usage_and_exit ()
{
    echo "Usage:"
    echo "test.sh up   [perf|npperf|perf3]     - Create test yaml and apply it"
    echo "test.sh down [perf|npperf|perf3]     - Delete test yaml"
    echo
    echo "test.sh build nptest"
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
  elif [[ "$1" = "down" ]]; then
	shift ; test_delete $@
  else
  	print_usage_and_exit
  fi
}

kube_test_cli $@
