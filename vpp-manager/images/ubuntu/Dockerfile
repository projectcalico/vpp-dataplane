FROM ubuntu:18.04

LABEL maintainer="nskrzypc@cisco.com"

RUN apt-get update \
 && apt-get install -y openssl libapr1 libnuma1 libmbedcrypto1 libmbedtls10 libmbedx509-0 \
 && rm -rf /var/lib/apt/lists/*

# set work directory
WORKDIR /root/

RUN mkdir /tmp/vpp

COPY *.deb /tmp/vpp/

RUN dpkg -i /tmp/vpp/vpp_*.deb \
    /tmp/vpp/vpp-plugin-core_*.deb \
    /tmp/vpp/vpp-plugin-dpdk_*.deb \
    /tmp/vpp/libvppinfra_*.deb

RUN rm -rf /tmp/vpp
ADD vpp-manager /usr/bin/

ENTRYPOINT ["/usr/bin/vpp-manager"]
