#!/bin/bash

set -o errexit


cd ${VPP_DIR}/extras/libmemif
rm -rf debug
mkdir -p debug/build
mkdir -p debug/install
cd debug/build
cmake ../.. \
	-DCMAKE_INSTALL_PREFIX=../install \
	-DCMAKE_BUILD_TYPE=Debug
make
make install

cd ${VPP_DIR}/extras/libmemif
rm -rf release
mkdir -p release/build
mkdir -p release/install
cd release/build
cmake ../.. \
	-DCMAKE_INSTALL_PREFIX=../install \
	-DCMAKE_BUILD_TYPE=Release
make
make install

cd ${VPP_DIR}

make build
make build-release

rm -f ./build-root/*.deb \
	./build-root/*.changes \
	./build-root/*.buildinfo
rm -rf ./build-root/debs

mkdir -p ./build-root/debs/debug
make pkg-deb-debug
mv ./build-root/*.deb \
	./build-root/*.changes \
	./build-root/*.buildinfo \
	./build-root/debs/debug

mkdir -p ./build-root/debs/release
make pkg-deb
mv ./build-root/*.deb \
	./build-root/*.changes \
	./build-root/*.buildinfo \
	./build-root/debs/release
