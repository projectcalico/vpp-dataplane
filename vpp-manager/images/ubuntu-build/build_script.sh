#!/bin/bash

set -o errexit

cd ${VPP_MGR_DIR}/vpp_build

make build-release
if [ "${NO_BUILD_DEBS}" != "true" ]; then
	rm -f ./build-root/*.deb ./build-root/*.changes ./build-root/*.buildinfo
	make pkg-deb
fi

