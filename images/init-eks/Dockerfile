FROM centos:8

LABEL maintainer="nskrzypc@cisco.com"

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

ADD init_eks.sh /init_eks.sh
ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
