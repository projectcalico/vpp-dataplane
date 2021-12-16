FROM calicovpp/test-iperf3

RUN mkdir /usr/local/lib/vpp && mkdir /etc/vpp/

ADD *.so /usr/local/lib/vpp/
ADD *.so.* /usr/local/lib/vpp/

ADD iperfcert.crt /etc/vpp/iperfcert.crt
ADD iperfcert.key /etc/vpp/iperfcert.key

ADD iperf3-vcl.sh /usr/local/bin/iperf3-vcl
ADD iperf3-tls-vcl.sh /usr/local/bin/iperf3-tls-vcl

EXPOSE 5201
ENTRYPOINT ["iperf3-vcl", "-4", "-s"]
