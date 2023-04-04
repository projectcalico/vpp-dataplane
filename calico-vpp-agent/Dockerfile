FROM ubuntu:22.04

LABEL maintainer="aloaugus@cisco.com"

ADD bin/gobgp /bin/gobgp
ADD bin/debug /bin/debug
ADD version /etc/calicovppversion
ADD bin/felix-api-proxy /bin/felix-api-proxy
ADD bin/calico-vpp-agent /bin/calico-vpp-agent

ENTRYPOINT ["/bin/calico-vpp-agent"]
