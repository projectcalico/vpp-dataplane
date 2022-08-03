#!/bin/bash

VPP_DIR=/repo/vpp-manager/vpp_build

# This targets a vpp that is compiled separately
# living in $VPP_DIR which is mounted
# from the host home by yaml/overlays/dev

# Assumes that
# vpp was built by make -C vpp-manager/ vpp

if [[ "x$DEBUG" != x ]]; then
  VPP="$VPP_DIR/build-root/install-vpp_debug-native/vpp"
else
  VPP="$VPP_DIR/build-root/install-vpp-native/vpp"
fi

export LD_LIBRARY_PATH=$VPP/lib/x86_64-linux-gnu
$VPP/bin/vppctl $@
