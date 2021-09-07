FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
	iperf 			                     \
	iproute2		                     \
	net-tools		                     \
	iptables		                     \
	iproute2		                     \
	iputils-ping		                 \
	inetutils-traceroute	             \
	netcat			                     \
	dnsutils                             \
	tcpdump                              \
	git                                  \
	build-essential                      \
	python3                              \
	unzip                                \
	curl

RUN mkdir -p /root/patches
ADD ./patches/*.patch /root/patches/

RUN cd /root && \
  git clone https://github.com/wg/wrk && \
  cd wrk && \
  patch -p1 < /root/patches/0001-no-keepalive-option.patch && \
  rm -r /root/patches && \
  make -j8

ADD wrk.py /root/wrk/wrk.py
WORKDIR /root/wrk

ENTRYPOINT ["tail", "-f", "/dev/null"]