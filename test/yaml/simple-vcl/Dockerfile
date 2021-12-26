FROM ubuntu:20.04

RUN apt-get update && apt-get install -y gcc \
	curl gnupg apt-transport-https  && \
	curl -L https://packagecloud.io/fdio/2110/gpgkey | apt-key add - && \
	echo "deb https://packagecloud.io/fdio/2110/ubuntu/ focal main" \
	  >> /etc/apt/sources.list.d/fdio_2110.list && \
	echo "deb-src https://packagecloud.io/fdio/2110/ubuntu/ focal main" \
	  >> /etc/apt/sources.list.d/fdio_2110.list && \
	apt-get update
RUN apt-get install -y vpp vpp-dev libvppinfra libvppinfra-dev
ADD vcl.conf /etc/vpp/vcl.conf

RUN mkdir /scratch

ADD client.c /scratch
ADD server.c /scratch
RUN cd /scratch && \
	gcc client.c -lvppcom -o client && \
	gcc server.c -lvppcom -o server

ENTRYPOINT ["tail", "-f", "/dev/null"]
