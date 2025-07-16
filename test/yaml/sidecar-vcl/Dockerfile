FROM ubuntu:22.04

RUN apt update && apt install -y \
    libunwind8 \
    libssh-4 \
 && apt clean \
 && rm -rf /var/lib/apt/lists/*

ADD libvppcom* /usr/local/lib/
ADD libvppinfra* /usr/local/lib/
ADD libvlibmemoryclient* /usr/local/lib/
ADD libvlibapi* /usr/local/lib/
ADD libvcl_ldpreload* /usr/local/lib/
ADD libsvm* /usr/local/lib/
ADD libcurlgnutls* /usr/local/lib/
ADD libmemif.so /usr/local/lib/
ADD version /version
RUN cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 /usr/local/lib/
RUN cp /usr/share/lintian/overrides/libssh-4 /usr/local/lib/

