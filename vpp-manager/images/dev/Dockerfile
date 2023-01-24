FROM ubuntu:22.04

LABEL maintainer="nskrzypc@cisco.com"

WORKDIR /root/

RUN apt-get update \
 && apt-get install -y openssl libapr1 libnuma1 libasan5 \
	  libmbedcrypto7 libmbedtls14 libmbedx509-1 libsubunit0 \
	  iptables iproute2 iputils-ping inetutils-traceroute \
	  netcat-openbsd ethtool gdb \
 && rm -rf /var/lib/apt/lists/*

ADD entrypoint.sh /usr/bin/entrypoint
ADD vpp.sh /usr/bin/vpp
ADD vppctl.sh /usr/bin/vppctl

RUN chmod +x /usr/bin/entrypoint /usr/bin/vppctl /usr/bin/vpp
ADD vppdev.sh /usr/bin/calivppctl

ENTRYPOINT ["/usr/bin/entrypoint"]
