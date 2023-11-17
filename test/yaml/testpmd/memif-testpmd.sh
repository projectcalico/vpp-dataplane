#!/bin/bash
LCORES=$1
if [[ x$LCORES = x ]]; then
	echo "Please provide a core list (e.g. 4-6)"
	echo "Cores available :"
	cat /sys/devices/system/cpu/online
	exit 1
fi
testpmd --iova-mode=va \
    -l $LCORES \
    --log-level pmd.net.memif:debug \
    --log-level eal:debug \
    --in-memory \
    --no-pci \
    --proc-type primary \
    --vdev=net_memif,role=client,socket=vpp/memif-eth0,socket-abstract=yes,zero-copy=no         \
    -- --auto-start \
    --forward-mode=5tswap               \
    --burst=32                          \
    --rxq=1                             \
    --txq=1                             \
    --nb-cores=1 \
    --no-numa
