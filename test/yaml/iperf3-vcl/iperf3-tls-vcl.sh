#!/bin/bash

TLS_ENGINE=${TLS_ENGINE:-1} # default to openssl

function generate_certs () {
	echo "No certificates found"
	echo "generating..."
	echo
	openssl genrsa -out /etc/vpp/iperfcert.key
	openssl req -new -key /etc/vpp/iperfcert.key \
				-out /etc/vpp/iperfcert.csr
	openssl x509 -req -days 365 \
				 -in /etc/vpp/iperfcert.csr \
				 -signkey /etc/vpp/iperfcert.key \
				 -out /etc/vpp/iperfcert.crt
}

function generate_vcl_conf () {
	echo "vcl {
  rx-fifo-size 4000000
  tx-fifo-size 4000000
  app-scope-local
  app-scope-global
  app-socket-api abstract:vpp/session
  tls-engine ${TLS_ENGINE}
}
" > /etc/vpp/vcl.conf
  echo "Using VCL conf :"
  cat /etc/vpp/vcl.conf
}

function run_tls_iperf3 () {
	if [ ! -f "/etc/vpp/iperfcert.crt" ]; then
	  generate_certs
	fi
	generate_vcl_conf
	VCL_CONFIG=/etc/vpp/vcl.conf \
	LD_PRELOAD=/usr/local/lib/vpp/libvcl_ldpreload.so \
	LD_LIBRARY_PATH=/usr/local/lib/vpp \
	LDP_TRANSPARENT_TLS=1 \
	LDP_TLS_CERT_FILE=/etc/vpp/iperfcert.crt \
	LDP_TLS_KEY_FILE=/etc/vpp/iperfcert.key \
	iperf3 $@
}

run_tls_iperf3 $@
