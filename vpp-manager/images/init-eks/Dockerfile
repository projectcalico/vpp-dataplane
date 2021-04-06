FROM centos:8

LABEL maintainer="nskrzypc@cisco.com"

ADD init_eks.sh /init_eks.sh
ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
