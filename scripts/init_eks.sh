#!/bin/bash

# This script applies the following customizations in EKS worker nodes:
#   1. configure 512 2MB hugepages
#   2. enable unsafe_noiommu_mode
#   3. download, build, install and load ENAv2 compatible igb_uio driver
#   4. download, build, install and load ENAv2 compatible vfio-pci driver
#
# These customizations are pre-requisites for running calico-vpp with the
# DPDK uplink driver in EKS.

while (( "$#" )) ; do
    eval $1
    shift
done

DPDK_VERSION=${DPDK_VERSION:=v20.11}
HUGEPAGES=${HUGEPAGES:=512}
BUILD_DIR=/tmp/build
IGB_UIO_PATH=/lib/modules/$(uname -r)/kernel/drivers/uio/igb_uio.ko

build_and_install_igb_uio ()
{
	if [ -f $IGB_UIO_PATH ]; then
		echo "Already built"
		return
	fi

	sudo yum install -y git python3 gcc make kernel-devel-$(uname -r)
	sudo pip3 install meson pyelftools ninja

	mkdir $BUILD_DIR && cd $BUILD_DIR

	git clone http://dpdk.org/git/dpdk
	cd dpdk && git checkout ${DPDK_VERSION} && cd ..
	git clone http://dpdk.org/git/dpdk-kmods
	cp -r ./dpdk-kmods/linux/igb_uio ./dpdk/kernel/linux/

	########## PATCHING DPDK ##########

	sed -i "s/subdirs = \['kni'\]/subdirs = \['igb_uio'\]/g" ./dpdk/kernel/linux/meson.build

	cat << EOF | tee ./dpdk/kernel/linux/igb_uio/meson.build
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

mkfile = custom_target('igb_uio_makefile',
        output: 'Makefile',
        command: ['touch', '@OUTPUT@'])

custom_target('igb_uio',
        input: ['igb_uio.c', 'Kbuild'],
        output: 'igb_uio.ko',
        command: ['make', '-C', get_option('kernel_dir') + '/build',
                'M=' + meson.current_build_dir(),
                'src=' + meson.current_source_dir(),
                'EXTRA_CFLAGS=-I' + meson.current_source_dir() +
                        '/../../../lib/librte_eal/include',
                'modules'],
        depends: mkfile,
        install: true,
        install_dir: get_option('kernel_dir') + '/extra/dpdk',
        build_by_default: get_option('enable_kmods'))
EOF

	sed -i "s/subdir('lib')/enabled_libs = [] #subdir('lib')/g" ./dpdk/meson.build
	sed -i "s/subdir('drivers')/#subdir('drivers')/g" ./dpdk/meson.build
	sed -i "s/subdir('usertools')/#subdir('usertools')/g" ./dpdk/meson.build
	sed -i "s/subdir('app')/#subdir('app')/g" ./dpdk/meson.build
	sed -i "s/subdir('doc')/#subdir('doc')/g" ./dpdk/meson.build
	sed -i "s/subdir('examples')/#subdir('examples')/g" ./dpdk/meson.build
	sed -i "s/install_subdir('examples',/#install_subdir('examples',/g" ./dpdk/meson.build
	sed -i "s@install_dir: get_option('datadir')@#install_dir: get_option('datadir')@g" ./dpdk/meson.build
	sed -i "s/exclude_files: 'meson.build')/#exclude_files: 'meson.build')/g" ./dpdk/meson.build

	########## PATCHING DPDK ##########

	cd ./dpdk
	meson build -Denable_kmods=true -Dkernel_dir=/lib/modules/$(uname -r)/
	ninja -C build

	sudo mv ./build/kernel/linux/igb_uio/igb_uio.ko ${IGB_UIO_PATH}
	sudo chown root:root ${IGB_UIO_PATH}
}

# NOTE: use sudo when/if running the script manually; not needed when running
# as part of cloud-init/userdata
configure_dpdk_interrupt_mode_support ()
{
	# download and build and install the vfio-pci driver with wc support
	# for ENAv2
	cd $BUILD_DIR
	git clone https://github.com/amzn/amzn-drivers.git
	cd amzn-drivers/userspace/dpdk/enav2-vfio-patch
	./get-vfio-with-wc.sh

	# load the driver
	modprobe vfio-pci

	# enable unsafe_noiommu_mode
	echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

	# persist the changes across reboots
	cat << EOF >> /etc/rc.d/rc.local
modprobe vfio-pci
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
EOF
	chmod +x /etc/rc.d/rc.local

	rm -rf $BUILD_DIR
}

configure_machine ()
{
	sudo rm -f /etc/cni/net.d/10-aws.conflist
	sudo modprobe uio
	if [ x$(lsmod | awk '{ print $1 }' | grep igb_uio) == x ]; then
		build_and_install_igb_uio
		sudo insmod /lib/modules/$(uname -r)/kernel/drivers/uio/igb_uio.ko wc_activate=1
	fi

	# configure hugepages and persist the config across reboots
	sudo sysctl -w vm.nr_hugepages=${HUGEPAGES}
	if [ -f /sys/fs/cgroup/hugetlb/kubepods/hugetlb.2MB.limit_in_bytes ]; then
		echo $((HUGEPAGES * 2 * 1024 * 1024)) | tee /sys/fs/cgroup/hugetlb/kubepods/hugetlb.2MB.limit_in_bytes
	fi
	echo "vm.nr_hugepages=${HUGEPAGES}" >> /etc/sysctl.conf
	systemctl restart kubelet
}

configure_machine
configure_dpdk_interrupt_mode_support
