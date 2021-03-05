FROM centos:6

LABEL maintainer="nskrzypc@cisco.com"

WORKDIR /

ADD 4.14.214-160.339.amzn2.x86_64.igb_uio.ko /igb_uio.ko
ADD init_eks.sh /

ENTRYPOINT ["/init_eks.sh"]
