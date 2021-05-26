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

RUN git clone https://github.com/MathiasRaoul/wrk.git
WORKDIR wrk
RUN make -j8
RUN cp wrk /usr/bin/
RUN apt-get install -y python3

ENTRYPOINT ["tail", "-f", "/dev/null"]