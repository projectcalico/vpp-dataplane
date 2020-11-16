FROM ubuntu:20.04

LABEL maintainer="nskrzypc@cisco.com"

RUN apt-get update \
 && apt-get install -y openssl libapr1 libnuma1 \
    libmbedcrypto3 libmbedtls12 libmbedx509-0 \
    iproute2 ifupdown ethtool \
 && rm -rf /var/lib/apt/lists/*

# set work directory
WORKDIR /root/

RUN mkdir /tmp/vpp

COPY *.deb /tmp/vpp/

RUN dpkg -i /tmp/vpp/libvppinfra_*.deb && \
    dpkg --unpack /tmp/vpp/vpp_*.deb  && \
    rm -f /var/lib/dpkg/info/vpp.postinst && \
    dpkg --configure vpp && \
    dpkg -i /tmp/vpp/vpp-plugin-core_*.deb \
    /tmp/vpp/vpp-plugin-dpdk_*.deb \
    /tmp/vpp/vpp-dbg_*.deb

RUN rm -rf /tmp/vpp
ADD vpp-manager /usr/bin/
ADD vppdev.sh /usr/bin/calivppctl

ENTRYPOINT ["/usr/bin/vpp-manager"]
