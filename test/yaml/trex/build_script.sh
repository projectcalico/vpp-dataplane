#!/bin/bash

set -o errexit

mkdir -p ${BUILD_DIR}/trex_build
cd ${BUILD_DIR}/trex_build

if [ ! -d trex-core ]; then
	git clone https://github.com/cisco-system-traffic-generator/trex-core.git
	cd trex-core
	git checkout ddce00f6fdea89850e0bf939fc82b96079fdcde5
	git apply /scratch/patches/0000-memif-abstract-trex.patch
	cd linux_dpdk
	./b configure
fi

cd ${BUILD_DIR}/trex_build/trex-core/linux_dpdk
./b build
