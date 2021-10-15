#!/bin/bash

# This targets a vpp that is compiled separately
# living in /home/hostuser/vpp which is mounted
# from the host home by yaml/overlays/dev

# Assumes that
# vpp lives in ~/vpp
# vpp-manager in ~/vpp-dataplane/vpp-manager

if [[ -f /home/hostuser/vpp/isrelease ]]; then
  VPP="/home/hostuser/vpp/build-root/install-vpp-native/vpp"
else
  VPP="/home/hostuser/vpp/build-root/install-vpp_debug-native/vpp"
fi

export LD_LIBRARY_PATH=$VPP/lib/x86_64-linux-gnu
$VPP/bin/vppctl $@
