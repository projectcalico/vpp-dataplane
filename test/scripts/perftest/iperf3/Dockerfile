FROM ubuntu:18.04

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
	tcpdump

EXPOSE 5201
ENTRYPOINT ["taskset", "-c", "17-23", "iperf3", "-s", "5201"]
