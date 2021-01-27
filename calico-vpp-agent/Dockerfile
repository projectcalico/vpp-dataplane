FROM calico/node:v3.18.0-0.dev-102-ge0f7235846ba

LABEL maintainer="aloaugus@cisco.com"

ADD dep/gobgp /bin/gobgp
ADD cmd/felix-api-proxy /bin/felix-api-proxy
ADD cmd/calico-vpp-agent /bin/calico-vpp-agent
ADD cmd/debug /bin/debug
ADD etc/service/calico-vpp-agent /etc/service/available/calico-vpp-agent
ADD version /etc/calicovppversion

RUN sed -i.orig \
    -e '/^case "\$CALICO_NETWORKING_BACKEND" in/a \\t"vpp" )\n\
\tcp -a /etc/service/available/calico-vpp-agent /etc/service/enabled/\n\
\t;;\n' \
    -e '/^if \[ "\$CALICO_DISABLE_FILE_LOGGING" = "true" \]; then/a \\trm -rf /etc/service/enabled/calico-vpp-agent/log' \
    /etc/rc.local

