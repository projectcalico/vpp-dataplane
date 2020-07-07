FROM centos:7

LABEL maintainer="aloaugus@cisco.com"

ENV VPP_VERSION=20.05-rc0~540_g77ea42b~b9261

ARG http_proxy

RUN yum install -y epel-release && \
    curl -s https://packagecloud.io/install/repositories/fdio/master/script.rpm.sh | bash && \
    yum install -y vpp-${VPP_VERSION} vpp-debuginfo-${VPP_VERSION} vpp-plugins-${VPP_VERSION}

ADD vpp-manager /

ENTRYPOINT ["/vpp-manager"]
