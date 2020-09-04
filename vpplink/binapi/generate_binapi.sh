#!/bin/bash

set -e

SOURCE="${BASH_SOURCE[0]}"
SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

GOVPP_DIR=$(go list -f '{{.Dir}}' -m git.fd.io/govpp.git)
BINAPI_GENERATOR=$SCRIPTDIR/bin/binapi-generator
VPPLINK_DIR=$SCRIPTDIR/..

function make_binapi_generator ()
{
  mkdir -p $SCRIPTDIR/bin
  cd $GOVPP_DIR
  go build -o $SCRIPTDIR/bin ./cmd/binapi-generator
}

function read_config ()
{
	echo "Using BINAPI_GENERATOR $($BINAPI_GENERATOR --version)"

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
	VPP_REMOTE_NAME=""

	VPP_VERSION=$(./build-root/scripts/version)
	VPP_COMMIT=$(git rev-parse --short HEAD)
	echo "Using commit : $VPP_COMMIT"
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
	  --output-dir=$SCRIPTDIR/$VPP_VERSION \
	  --no-source-path-info \
	  --debug \
	  ikev2 \
	  gso \
	  interface \
	  ip \
	  ipip \
	  ipsec \
	  ip_neighbor \
	  tapv2 \
	  nat \
	  cnat \
	  calico \
	  af_packet \
	  feature \
	  ip6_nd \
	  punt \
	  vpe
}

function update_version_number ()
{
	echo "Update version number with $VPP_VERSION ? [yes/no] "
	read RESP

	if [[ x$RESP = xyes ]]; then
		find $VPPLINK_DIR -name '*.go' \
			-exec sed -i 's@github.com/projectcalico/vpp-dataplane/vpplink/binapi/[.~0-9a-z_-]*/'"@github.com/projectcalico/vpp-dataplane/vpplink/binapi/$VPP_VERSION/@g" {} \;
	fi
}

make_binapi_generator
read_config
generate_vpp_apis
generate_govpp_apis
update_version_number

