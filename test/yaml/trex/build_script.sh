#!/bin/bash

set -o errexit

mkdir -p ${BUILD_DIR}/trex_build
cd ${BUILD_DIR}/trex_build

if [ ! -d trex-core ]; then
	git clone -b v3.06 https://github.com/cisco-system-traffic-generator/trex-core.git
	cd trex-core/linux_dpdk
	./b configure
fi

cd ${BUILD_DIR}/trex_build/trex-core/linux_dpdk
./b build
