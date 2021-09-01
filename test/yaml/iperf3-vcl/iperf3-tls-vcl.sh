#!/bin/bash

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

function run_tls_iperf3 () {
	if [ ! -f "/etc/vpp/iperfcert.crt" ]; then
	  generate_certs
	fi
	VCL_CONFIG=/etc/vpp/vcl.conf \
	LD_PRELOAD=/usr/local/lib/vpp/libvcl_ldpreload.so \
	LD_LIBRARY_PATH=/usr/local/lib/vpp \
	LDP_TRANSPARENT_TLS=1 \
	LDP_TLS_CERT_FILE=/etc/vpp/iperfcert.crt \
	LDP_TLS_KEY_FILE=/etc/vpp/iperfcert.key \
	iperf3 $@
}

run_tls_iperf3 $@
