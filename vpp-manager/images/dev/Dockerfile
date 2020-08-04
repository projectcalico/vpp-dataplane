FROM ubuntu:20.04

LABEL maintainer="nskrzypc@cisco.com"

WORKDIR /root/

RUN apt-get update \
 && apt-get install -y openssl libapr1 libnuma1 libasan5 \
	  libmbedcrypto3 libmbedtls12 libmbedx509-0 \
	  iptables iproute2 iputils-ping inetutils-traceroute \
	  netcat-openbsd ethtool gdb \
 && rm -rf /var/lib/apt/lists/*

ADD entrypoint /usr/bin/

RUN chmod +x /usr/bin/entrypoint

ENTRYPOINT ["/usr/bin/entrypoint"]
