#!/bin/bash

set -e

SOURCE="${BASH_SOURCE[0]}"
SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

function read_config ()
{
	echo "Input VPP full path : "
	read VPP_DIR

	if [[ ! -d $VPP_DIR ]]; then
		echo "Couldnt find anything at <$VPP_DIR>"
		exit 1
	fi

	pushd $VPP_DIR > /dev/null
	VPP_REMOTE_NAME=""

	VPP_VERSION=$(./build-root/scripts/version)
	VPP_COMMIT=$(git rev-parse --short HEAD)
	echo "Using commit : $VPP_COMMIT"
	popd > /dev/null
}

function generate_govpp_api ()
{
	NAME="$1.api.json"
	echo "Generating API $NAME"
	find $VPP_DIR/build-root/install-vpp-native/vpp/share/vpp/api/ -name "$NAME" \
		-exec binapi-generator --input-file={} --output-dir=$SCRIPTDIR/$VPP_VERSION \;
}

function generate_vpp_apis ()
{
	pushd $VPP_DIR > /dev/null
	make json-api-files
	popd > /dev/null
}

function fixup_govpp_apis ()
{
	sed -i 's/LabelStack \[\]FibMplsLabel/LabelStack \[16\]FibMplsLabel/g' \
	  $SCRIPTDIR/$VPP_VERSION/ip/ip.ba.go
}

function cleanup_govpp_apis ()
{
	find . -path $SCRIPTDIR/$VPP_VERSION -prune -o -name '*.go' \
			-exec sed -i '/\/\/ source:/d' {} \;
}

function generate_govpp_apis ()
{
	generate_govpp_api ikev2
	generate_govpp_api gso
	generate_govpp_api interface
	generate_govpp_api ip
	generate_govpp_api ipip
	generate_govpp_api ipsec
	generate_govpp_api ip_neighbor
	generate_govpp_api tapv2
	generate_govpp_api nat
	generate_govpp_api calico
	generate_govpp_api af_packet
	generate_govpp_api feature

	cleanup_govpp_apis
	fixup_govpp_apis
}

function update_version_number ()
{
	echo "Update version number with $VPP_VERSION ? [yes/no] "
	read RESP

	if [[ x$RESP = xyes ]]; then
		find . -path ./binapi -prune -o -name '*.go' \
			-exec sed -i 's@github.com/projectcalico/vpp-dataplane/vpplink/binapi/[.~0-9a-z_-]*/'"@github.com/projectcalico/vpp-dataplane/vpplink/binapi/$VPP_VERSION/@g" {} \;
	fi
}

read_config
generate_vpp_apis
generate_govpp_apis
update_version_number

