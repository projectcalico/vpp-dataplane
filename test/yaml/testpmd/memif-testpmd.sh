#!/bin/bash
testpmd --iova-mode=va \
    -l 13-16 \
    --log-level pmd.net.memif:debug \
    --log-level eal:debug \
    --no-pci \
    --no-huge \
    --proc-type auto \
    --vdev=net_memif,role=client,socket=memif,socket-abstract=yes,zero-copy=no         \
    -- --auto-start \
    --forward-mode=5tswap               \
    --burst=32                          \
    --rxq=1                             \
    --txq=1                             \
    --nb-cores=1
