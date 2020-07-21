  #!/bin/bash

set -e
DISABLE_KUBE_PROXY=

if [[ "$X" != "" ]]; then set -x ; fi

function check ()
{
	if [ -z "$1" ]; then
		echo "required variable is blank"
		exit 1
	fi
}

function icheck ()
{
	if [[ ! $1 =~ ^-?[0-9]+$ ]]; then
		echo "required input is not an int"
		exit 1
	fi
}

function lcheck ()
{
	while (( "$#" )) ; do
		check $1
    	shift
	done
}

function licheck ()
{
	while (( "$#" )) ; do
		icheck $1
    	shift
	done
}

function green ()
{
  printf "\e[0;32m$1\e[0m\n"
}

function red ()
{
  printf "\e[0;31m$1\e[0m\n"
}

function name_from_pci ()
{
	check $1
	echo $(ls /sys/bus/pci/devices/$1/net/ | sed s./..g)
}

find_node_pod () # NODE, POD
{
  echo $(kubectl get pods -n kube-system --field-selector="spec.nodeName=$NODE" | grep $POD | cut -d ' ' -f 1)
}

exec_node () # C, POD, NODE
{
  kubectl exec -it -n kube-system $(find_node_pod) -c $C -- $@
}

log_node () # C, POD, NODE
{
  kubectl logs $FOLLOW -n kube-system $(find_node_pod) -c $C
}

function 6safe () { if [[ "$USE_IP6" = "yes" ]]; then echo "[$1]" ; else echo "$1" ; fi }
function get_listen_addr () { if [[ "$USE_IP6" = "yes" ]]; then echo "::" ; else echo "0.0.0.0" ; fi }

