#!/bin/bash

set -o errexit

cd /root/vpp-manager/vpp_build

make build-release
rm -f ./build-root/*.deb ./build-root/*.changes ./build-root/*.buildinfo
make pkg-deb

