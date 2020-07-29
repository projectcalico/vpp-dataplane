#!/bin/bash

set -o errexit

cd /root/vpp-manager/vpp_build
make install-dep

git apply ../vpp-build.patch
make build-release
rm -f ./build-root/*.deb ./build-root/*.changes ./build-root/*.buildinfo
make pkg-deb
git apply -R ../vpp-build.patch

