FROM ubuntu:20.04

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
	tcpdump								 \
	netperf

ADD entrypoint.sh /usr/bin/entrypoint
RUN chmod +x /usr/bin/entrypoint

ENTRYPOINT ["/usr/bin/entrypoint"]
