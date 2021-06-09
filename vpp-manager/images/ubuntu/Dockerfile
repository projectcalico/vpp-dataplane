FROM ubuntu:20.04

LABEL maintainer="nskrzypc@cisco.com"

RUN apt-get update \
 && apt-get install -y openssl libapr1 libnuma1 \
    libmbedcrypto3 libmbedtls12 libmbedx509-0 libsubunit0 \
    iproute2 ifupdown ethtool libnl-3-dev libnl-route-3-dev \
 && rm -rf /var/lib/apt/lists/*

# set work directory
WORKDIR /root/

RUN mkdir /tmp/vpp

COPY *.deb /tmp/vpp/

RUN export VPP_INSTALL_SKIP_SYSCTL=1 && \
    dpkg -i /tmp/vpp/libvppinfra_*.deb \
    /tmp/vpp/vpp_*.deb \
    /tmp/vpp/vpp-plugin-core_*.deb \
    /tmp/vpp/vpp-plugin-dpdk_*.deb \
    /tmp/vpp/vpp-dbg_*.deb

RUN rm -rf /tmp/vpp
ADD vpp-manager /usr/bin/
ADD vppdev.sh /usr/bin/calivppctl
ADD version /etc/calicovppversion

ENTRYPOINT ["/usr/bin/vpp-manager"]
