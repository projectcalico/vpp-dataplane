#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function create_service()
{
    SERVICE_NAME=$1
	SERVICE_TYPE=$2
	template_file=$SCRIPTDIR/templates/service.$SERVICE_TYPE.yml.template
	export SERVICE_NAME=$1
	cat $template_file | envsubst | tee -a /tmp/testcalico.yaml
}

function create_services ()
{
	num_start=$1
	num_end=$2
	YAML_=""

	echo "" | tee /tmp/testcalico.yaml
	for i in `seq $num_start $num_end`;
	do
		tmp=$(echo $(create_service service-$3-$i $3))
		YAML_="${YAML_} ${tmp}"
	done
	kubectl apply -f /tmp/testcalico.yaml 
}

function start_test ()
{
	NB_SERVICES=$1
	INC=$2
    CREATED_SERVICES=0

	START=0
	END=$INC
	while [ $NB_SERVICES -gt $START ]
	do
		create_services $START $END nginx
		START=$(($START+$INC))
		END=$(($END+$INC))
	done
}

function test_cli()
{
   if [[ "$1" = "services" ]]; then
	shift
	cre $@
   elif [[ "$1" = "clean" ]]; then
	shift
	clean_env $@
  elif [[ "$1" = "test" ]]; then
	shift
	start_test $@
  else
  	print_usage_and_exit
  fi
}

function print_usage_and_exit ()
{
	echo "Usage :"
	echo "utils.sh services NB_INC TOTAL_SERVICE"
	echo
	exit 1
}

test_cli $@