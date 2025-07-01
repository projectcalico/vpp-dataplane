#!/bin/bash

set -o errexit

if [ "$CUSTOM_VPP_DIR" -eq 1 ]; then
	cd ${VPP_DIR}
else
	cd ${VPP_DIR}/vpp_build
fi

make build-release
if [ "${NO_BUILD_DEBS}" != "true" ]; then
	rm -f ./build-root/*.deb ./build-root/*.changes ./build-root/*.buildinfo
	make pkg-deb
fi

