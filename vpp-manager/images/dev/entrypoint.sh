#!/bin/bash

VPP_MANAGER=/repo/vpp-manager/images/ubuntu/vpp-manager

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
# living in $VPP_DIR which is mounted
# from the host home by yaml/overlays/dev

# Assumes that
# vpp was built by make -C vpp-manager/ vpp

if [[ "x$DEBUG" == xsleep ]]; then
  tail -f /dev/null
else
  $VPP_MANAGER &
  child=$!
  while kill -0 $child > /dev/null 2>&1
  do
      wait $child
  done
fi