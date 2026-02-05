#!/bin/bash

function generate_trex_py () {
	IP_ADDR=$(ip -4 addr show eth0 | grep inet | awk '{print $2}' | cut -d '/' -f 1)
	export SRC_ADDRESS=${SRC_ADDRESS:-$IP_ADDR}
	export SRC_ADDRESS2=${SRC_ADDRESS2:-$SRC_ADDRESS}
	export DST_ADDRESS=${DST_ADDRESS:-1.2.3.4}
	export DST_PORT=${DST_PORT:-4444}
	export SRC_PORT=${SRC_PORT:-4444}
	export SRC_PORT2=${SRC_PORT2:-$SRC_PORT}
	echo "Using [$SRC_ADDRESS..$SRC_ADDRESS2]:[$SRC_PORT..$SRC_PORT2] -> $DST_ADDRESS:$DST_PORT"
	cat /trex-scripts/trex_template.py | envsubst > /trex-scripts/trex.py
	echo "$ trex-console"
	echo "$ start -f /trex-scripts/trex.py -p 0 -m 10mbps"
	echo "## To show stats (use q to quit)"
	echo "$ tui"
	echo "## To update to full speed"
	echo "$ update -m 100%"
	echo "## To stop traffic generation"
	echo "$ stop -a"
}

generate_trex_py

export PYTHONPATH=/usr/local/share/trex-interactive
export TREX_EXT_LIBS=/usr/local/share/trex-external_libs

python3 -m trex.console.trex_console $@
