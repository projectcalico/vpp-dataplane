#!/bin/bash

NR_HUGEPAGES=${NR_HUGEPAGES:-128}

sysctl -w vm.nr_hugepages=$NR_HUGEPAGES
modprobe uio
if [ x$(lsmod | awk '{ print $1 }' | grep igb_uio) == x ]
then
  insmod /igb_uio.ko wc_activate=1
fi

# This is needed to acknowledge hugepages limits in
# /sys/fs/cgroup/hugetlb/kubepods/hugetlb.2MB.limit_in_bytes
# Otherwise we'll need to restart the docker service

cat << EOF | chroot /host
echo $((NR_HUGEPAGES * 2 * 1024 * 1024)) | \
  tee /sys/fs/cgroup/hugetlb/kubepods/hugetlb.2MB.limit_in_bytes

systemctl restart kubelet
EOF
