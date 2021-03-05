#!/bin/bash
# The target AMI is : ami-047e3ad49b70ed809

sudo yum install -y \
  git gcc cmake3 patch numactl-devel \
  ninja-build kernel-devel-$(uname -r)

wget https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/vpp-manager/images/init-eks/build_igb_uio/patch
git clone https://gerrit.fd.io/r/vpp && cd vpp
git apply ../patch
make build-release

find . -name '*.ko'

# In order to build the full VPP locally, you also have to :
# sudo yum install openssl-devel clang
# sudo pip3 install ply



