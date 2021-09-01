#!/bin/bash
VCL_CONFIG=/etc/vpp/vcl.conf \
LD_PRELOAD=/usr/local/lib/vpp/libvcl_ldpreload.so \
LD_LIBRARY_PATH=/usr/local/lib/vpp \
iperf3 $@
