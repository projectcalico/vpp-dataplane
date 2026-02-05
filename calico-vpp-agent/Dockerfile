FROM ubuntu:22.04

LABEL maintainer="aloaugus@cisco.com"

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

ADD bin/gobgp /bin/gobgp
ADD version /etc/calicovppversion
ADD bin/felix-api-proxy /bin/felix-api-proxy
ADD bin/calico-vpp-agent /bin/calico-vpp-agent

ENTRYPOINT ["/bin/calico-vpp-agent"]
