#!/bin/bash
# The target AMI is : ami-047e3ad49b70ed809

sudo yum install git gcc cmake3 patch numactl-devel ninja-build kernel-devel-$(uname -r)
git clone https://gerrit.fd.io/r/vpp

cd vpp
git apply ../patch
cd build/external
make dpdk-config
make dpdk-install

VPP_BUILD=./build-root/install-vpp_debug-native/
echo "$VPP_BUILD/external/lib/modules/$(uname -r)/extra/dpdk/igb_uio.ko"

# In order to build the full VPP locally, you also have to :
# sudo yum install openssl-devel
# sudo pip3 isntall ply



