FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
	python3 libzmq5 python3-distutils iproute2 \
	nano gettext

ADD trex-console.sh /usr/local/bin/trex-console
ADD trex-start.sh /usr/local/bin/trex-start

ADD trex-bins/t-rex-64 /usr/local/bin/trex
ADD trex-bins/trex-interactive /usr/local/share/trex-interactive
ADD trex-bins/trex-external_libs /usr/local/share/trex-external_libs
ADD trex-bins/libbpf-64.so /usr/lib/libbpf-64.so

RUN mkdir -p /trex-scripts
ADD trex_template.py /trex-scripts

ENTRYPOINT ["tail", "-f", "/dev/null"]
