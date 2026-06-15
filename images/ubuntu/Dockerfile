FROM ubuntu:22.04

LABEL maintainer="nskrzypc@cisco.com"

RUN apt-get update \
 && apt-get install -y openssl libapr1 libnuma1 \
    libmbedcrypto7 libmbedtls14 libmbedx509-1 libsubunit0 \
    iproute2 ifupdown ethtool libnl-3-dev libnl-route-3-dev \
    libpcap0.8 libunwind8 iptables \
    gdb \
 && rm -rf /var/lib/apt/lists/*

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

# set work directory
WORKDIR /root/

RUN mkdir /tmp/vpp

COPY artifacts/release/*.deb /tmp/vpp/

RUN export VPP_INSTALL_SKIP_SYSCTL=1 && \
    dpkg -i /tmp/vpp/libvppinfra_*.deb \
	    /tmp/vpp/vpp_*.deb \
	    /tmp/vpp/vpp-plugin-core_*.deb \
	    /tmp/vpp/vpp-plugin-dpdk_*.deb \
	    /tmp/vpp/vpp-dbg_*.deb \
	    /tmp/vpp/vpp-plugin-devtools_*.deb && \
    rm -rf /tmp/vpp

# vpp-manager binary and helper script
ADD bin/vpp-manager /usr/bin/
ADD bin/vppdev.sh /usr/bin/calivppctl
ADD artifacts/release/calicovppversion /etc/calicovppversion

# agent binaries
ADD bin/calico-vpp-agent /bin/calico-vpp-agent
ADD bin/felix-api-proxy /bin/felix-api-proxy
ADD bin/gobgp /bin/gobgp

# multinet-monitor binary
ADD bin/multinet-monitor /bin/multinet-monitor

# init-eks scripts
ADD bin/init_eks.sh /bin/init_eks.sh
ADD bin/init_eks_entrypoint.sh /bin/init_eks_entrypoint.sh

ENTRYPOINT ["/usr/bin/vpp-manager"]
