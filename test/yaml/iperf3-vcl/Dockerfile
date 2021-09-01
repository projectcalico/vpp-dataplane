FROM calicovpp/test-iperf3

ADD vcl.conf /etc/vpp/vcl.conf
RUN mkdir /usr/local/lib/vpp
ADD *.so /usr/local/lib/vpp/
ADD *.so.* /usr/local/lib/vpp/

ADD iperfcert.crt /etc/vpp/iperfcert.crt
ADD iperfcert.key /etc/vpp/iperfcert.key

ADD iperf3-vcl.sh /usr/local/bin/iperf3-vcl
ADD iperf3-tls-vcl.sh /usr/local/bin/iperf3-tls-vcl

EXPOSE 5201
ENTRYPOINT ["tail", "-f", "/dev/null"]
