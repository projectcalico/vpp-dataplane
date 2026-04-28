#!/bin/bash

cp /init_eks.sh /host/usr/local/bin/init_eks.sh
cat << EOF | chroot /host
/usr/local/bin/init_eks.sh
EOF

# sleep 10 years
sleep 315360000
