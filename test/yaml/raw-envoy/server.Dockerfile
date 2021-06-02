FROM envoyproxy/envoy

RUN apt-get update && apt-get install -y netcat iperf3 numactl

ADD certs/cacert.pem /etc/certs/cacert.pem
ADD certs/servercert.pem /etc/certs/servercert.pem
ADD certs/serverkey.pem /etc/certs/serverkey.pem

# server specifics

ADD server-entrypoint.sh /run/server-entrypoint.sh

RUN chmod +x /run/server-entrypoint.sh

ADD certs/cacert.pem /etc/certs/cacert.pem
ADD certs/servercert.pem /etc/certs/servercert.pem
ADD certs/serverkey.pem /etc/certs/serverkey.pem

ENTRYPOINT ["/run/server-entrypoint.sh"]