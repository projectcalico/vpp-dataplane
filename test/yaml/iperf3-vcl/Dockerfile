FROM calicovpp/test-iperf3

ADD vcl.conf /etc/vpp/vcl.conf
RUN mkdir /usr/local/lib/vpp
ADD *.so /usr/local/lib/vpp/
ADD *.so.* /usr/local/lib/vpp/

ADD iperf3-vcl.sh /usr/local/bin/iperf3-vcl

EXPOSE 5201
ENTRYPOINT ["tail", "-f", "/dev/null"]
