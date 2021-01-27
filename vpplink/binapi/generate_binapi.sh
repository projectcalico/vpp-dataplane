#!/bin/bash

set -e

SOURCE="${BASH_SOURCE[0]}"
SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

GOVPP_DIR=$(go list -f '{{.Dir}}' -m git.fd.io/govpp.git)
BINAPI_GENERATOR=$SCRIPTDIR/bin/binapi-generator
VPPLINK_DIR=$SCRIPTDIR/..

VPP_GOAPI_DIR=$SCRIPTDIR/vppapi
VPP_API_IMPORT_PREFIX=github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi

function make_binapi_generator ()
{
  mkdir -p $SCRIPTDIR/bin
  cd $GOVPP_DIR
  go build -o $SCRIPTDIR/bin ./cmd/binapi-generator
}

function read_config ()
{

	if [[ x$VPP_DIR == x ]]; then
		echo "Input VPP full path : "
		read VPP_DIR
	fi

	if [[ ! -d $VPP_DIR ]]; then
		echo "Couldnt find anything at <$VPP_DIR>"
		exit 1
	fi
	VPP_API_DIR=$VPP_DIR/build-root/install-vpp-native/vpp/share/vpp/api/

	pushd $VPP_DIR > /dev/null
	rm -rf $VPP_GOAPI_DIR
	git fetch origin
	VPP_VERSION=$(./build-root/scripts/version)
	VPP_BASE_COMMIT=$(git log $(git log origin/master..HEAD --oneline | tail -1 | awk '{print $1}')^ --oneline -1)
	mkdir $VPP_GOAPI_DIR
	echo "VPP Version                 : $VPP_VERSION"                     > $VPP_GOAPI_DIR/generate.log
	echo "Binapi-generator version    : $($BINAPI_GENERATOR --version)"  >> $VPP_GOAPI_DIR/generate.log
	echo "VPP Base commit             : $VPP_BASE_COMMIT"                >> $VPP_GOAPI_DIR/generate.log
	echo "------------------ Cherry picked commits --------------------" >> $VPP_GOAPI_DIR/generate.log
	git log origin/master..HEAD --oneline                                >> $VPP_GOAPI_DIR/generate.log
	echo "-------------------------------------------------------------" >> $VPP_GOAPI_DIR/generate.log
	cat $VPP_GOAPI_DIR/generate.log
	popd > /dev/null
}

function generate_vpp_apis ()
{
	pushd $VPP_DIR > /dev/null
	make json-api-files
	popd > /dev/null
}

function generate_govpp_apis ()
{
	$BINAPI_GENERATOR \
	  --input-dir=$VPP_API_DIR \
	  --output-dir=$VPP_GOAPI_DIR \
	  --import-prefix=$VPP_API_IMPORT_PREFIX \
	  --no-source-path-info \
	  --no-version-info \
	  ikev2 \
	  gso \
	  interface \
	  ip \
	  ipip \
	  ipsec \
	  ip_neighbor \
	  tapv2 \
	  nat44 \
	  cnat \
	  af_packet \
	  feature \
	  ip6_nd \
	  punt \
	  vxlan \
	  af_xdp \
	  vpe \
	  virtio \
	  avf \
	  wireguard \
      capo
}

make_binapi_generator
read_config
generate_vpp_apis
generate_govpp_apis

