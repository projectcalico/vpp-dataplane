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

if [[ "$X" != "" ]]; then set -x ; fi

function green ()
{
  printf "\e[0;32m$1\e[0m\n"
}

function red ()
{
  printf "\e[0;31m$1\e[0m\n"
}

function blue ()
{
  printf "\e[0;34m$1\e[0m\n"
}

function grey ()
{
  printf "\e[0;37m$1\e[0m\n"
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

