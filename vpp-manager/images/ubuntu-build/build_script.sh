#!/bin/bash

set -o errexit

cd /root/vpp-manager/vpp_build

make build
rm -f ./build-root/*.deb ./build-root/*.changes ./build-root/*.buildinfo
make pkg-deb-debug

