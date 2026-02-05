FROM ubuntu:22.04

LABEL maintainer="hbouatto@cisco.com"

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

ADD watcher /bin/watcher

ENTRYPOINT ["/bin/watcher"]
