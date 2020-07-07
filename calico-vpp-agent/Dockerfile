FROM calico/node:v3.9.1

ADD dep/gobgp /bin/gobgp
ADD cmd/calico-vpp-agent /bin/calico-vpp-agent
ADD etc/service/calico-vpp-agent /etc/service/available/calico-vpp-agent

RUN sed -i.orig '/^case "\$CALICO_NETWORKING_BACKEND" in/a \\t"vpp" )\n\
\tcp -a /etc/service/available/calico-vpp-agent /etc/service/enabled/\n\
\tsh -c '\''for file in `find /etc/calico/confd/conf.d/ -not -name '\''tunl-ip.toml'\'' -type f`; do rm $file; done'\''\n\
\tcp -a /etc/service/available/confd /etc/service/enabled/\n\
\t;;\n' /etc/rc.local
