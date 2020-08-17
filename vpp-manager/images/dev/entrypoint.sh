#!/bin/bash

VPP_MANAGER=/home/hostuser/vpp-dataplane/vpp-manager/images/ubuntu/vpp-manager

_trap() {
  echo "Caught $1 signal!"
  kill -$1 "$child" 2>/dev/null
}

trap "_trap TERM" SIGTERM
trap "_trap KILL" SIGKILL
trap "_trap INT" SIGINT
trap "_trap QUIT" SIGQUIT
trap "_trap HUP" SIGHUP
trap "_trap ABRT" SIGABRT

# This targets a vpp that is compiled separately
# living in /home/hostuser/vpp which is mounted
# from the host home by yaml/overlays/dev

# Assumes that
# vpp lives in ~/vpp
# vpp-manager in ~/vpp-dataplane/vpp-manager

if [[ -f /home/hostuser/vpp/isrelease ]]; then
  VPP="/home/hostuser/vpp/build-root/install-vpp-native/vpp/"
else
  VPP="/home/hostuser/vpp/build-root/install-vpp_debug-native/vpp/"
fi

if [[ -f /home/hostuser/vpp/istailnull ]]; then
  tail -f /dev/null
else
  $VPP_MANAGER &
  child=$!
  while kill -0 $child > /dev/null 2>&1
  do
      wait $child
  done
fi