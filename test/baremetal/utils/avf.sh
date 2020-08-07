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

if [ $USER != "root" ] ; then
        echo "Restarting script with sudo..."
        sudo $0 ${*}
        exit
fi

setup () {
  cd /sys/bus/pci/devices/${1}
  driver=$(basename $(readlink driver))
  if [ "${driver}" != "i40e" ]; then
    echo ${1} | tee driver/unbind
    echo ${1} | tee /sys/bus/pci/drivers/i40e/bind
  fi
  ifname=$(basename net/*)
  echo 0 | sudo tee sriov_numvfs > /dev/null
  echo 1 | sudo tee sriov_numvfs > /dev/null
  ip link set dev ${ifname} vf 0 mac ${2}
  ip link show dev ${ifname}
  vf=$(basename $(readlink virtfn0))
  echo ${vf} | tee virtfn0/driver/unbind
  echo vfio-pci | tee virtfn0/driver_override
  echo ${vf} | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
  echo  | tee virtfn0/driver_override
  echo ${vf} > ~/vpp/vfpci
}

if [ x"$@" = "" ]; then
	echo "Usage"
	echo "avf.sh <PCI> <MAC>"
	echo
	echo "avf.sh 0000:3b:00.0 00:11:22:33:44:00"
	echo "will create one VF on PF 0000:3b:00.0"
	echo "and assign the MAC address 00:11:22:33:44:00"
	echo
	echo "the resulting PCI ID can be used in vpp"
	echo "with create interface avf <PCIID>"
else
  setup $@
fi
