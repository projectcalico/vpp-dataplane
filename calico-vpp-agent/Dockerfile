FROM ubuntu:20.04

LABEL maintainer="aloaugus@cisco.com"

ADD dep/gobgp /bin/gobgp
ADD cmd/debug /bin/debug
ADD version /etc/calicovppversion
ADD cmd/felix-api-proxy /bin/felix-api-proxy
ADD cmd/calico-vpp-agent /bin/calico-vpp-agent

ENTRYPOINT ["/bin/calico-vpp-agent"]
