FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
	iperf3			                     \
	iproute2		                     \
	net-tools		                     \
	iptables		                     \
	iproute2		                     \
	iputils-ping		                 \
	inetutils-traceroute	             \
	netcat			                     \
	dnsutils                             \
	libunwind8							 \
	tcpdump

EXPOSE 5201
ENTRYPOINT ["taskset", "-c", "17-23", "iperf3", "-s", "5201"]
