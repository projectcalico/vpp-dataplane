FROM sknat/iperf3

ADD vcl.conf /etc/vpp/vcl.conf
RUN mkdir /usr/local/lib/vpp
ADD *.so /usr/local/lib/vpp/
ADD *.so.* /usr/local/lib/vpp/

ENV VCL_CFG=/etc/vpp/vcl.conf
ENV LDP_PATH=/usr/local/lib/vpp/libvcl_ldpreload.so
ENV LD_LIBRARY_PATH=/usr/local/lib/vpp

EXPOSE 5201
ENTRYPOINT ["tail", "-f", "/dev/null"]
