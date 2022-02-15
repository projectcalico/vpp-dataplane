FROM ubuntu:20.04

LABEL maintainer="aloaugus@cisco.com"

# DEB_DEPENDS from VPP's Makefile, added here to be cached
# This must be updated when the list of VPP dependencies change
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
	curl build-essential autoconf automake ccache \
	debhelper dkms git libtool libapr1-dev dh-python \
	libconfuse-dev git-review exuberant-ctags cscope pkg-config \
	lcov chrpath autoconf libnuma-dev \
	python3-all python3-setuptools check \
	libffi-dev python3-ply libmbedtls-dev \
	cmake ninja-build uuid-dev python3-jsonschema python3-yaml \
	python3-venv \
	python3-dev \
	libnl-3-dev libnl-route-3-dev \
	enchant \
	python3-virtualenv \
	libssl-dev \
	libelf-dev \
	clang-11 clang-format-11 clang-format-10 \
	enchant-2 \
	libffi7 \
	libmnl0 \
	libiperf0 \
	iperf3 \
	libmnl-dev

WORKDIR /

# Hack around tar issue setting symlinks mtime on mac os bind mounts
# This issue only happens on the dpdk tarball, and the -m flag causes
# nasm to try to rebuild things that fail, hence the if
RUN cd /usr/bin; mv tar tar.orig && \
    echo '#!/bin/bash\nif [[ "$*" == *dpdk* || "$*" == *rdma* ]] ; then ARGS="-m" ; fi\n/usr/bin/tar.orig $ARGS --no-same-owner "$@"' > tar && \
    chmod a+x tar

ADD build_script.sh /

CMD "/build_script.sh"
