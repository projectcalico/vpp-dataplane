#!/bin/bash

set -o errexit


cd ${VPP_DIR}/extras/libmemif
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=../libmemif-install
make
make install
cp ../libmemif-install/lib/libmemif.so ${VPP_DIR}/extras/libmemif/build/lib/

cd ${VPP_DIR}

make build-release
if [ "${NO_BUILD_DEBS}" != "true" ]; then
	rm -f ./build-root/*.deb ./build-root/*.changes ./build-root/*.buildinfo
	make pkg-deb
fi
