#!/bin/bash

function generate_vcl_conf () {
	echo "vcl {
  rx-fifo-size 4000000
  tx-fifo-size 4000000
  app-scope-local
  app-scope-global
  app-socket-api abstract:vpp/session
}
" > /etc/vpp/vcl.conf
  echo "Using VCL conf :"
  cat /etc/vpp/vcl.conf
}

function run_iperf3 () {
	generate_vcl_conf
	VCL_CONFIG=/etc/vpp/vcl.conf \
	LD_PRELOAD=/usr/local/lib/vpp/libvcl_ldpreload.so \
	LD_LIBRARY_PATH=/usr/local/lib/vpp \
	iperf3 $@
}

run_iperf3 $@
