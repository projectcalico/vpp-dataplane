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
	tcpdump \
	git \
	build-essential \
	curl

RUN git clone https://github.com/noahgibbs/wrk.git
WORKDIR wrk
RUN git checkout 51efed8ec10e95c0cd04f6c84614941e70379924
RUN make -j8
RUN cp wrk /usr/bin/

ADD entrypoint.sh /usr/bin/entrypoint
RUN chmod +x /usr/bin/entrypoint

ENTRYPOINT ["/usr/bin/entrypoint"]