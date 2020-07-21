FROM envoyproxy/envoy

RUN apt-get update && apt-get install -y netcat iperf3 numactl

ADD certs/cacert.pem /etc/certs/cacert.pem
ADD certs/clientcert.pem /etc/certs/clientcert.pem
ADD certs/clientkey.pem /etc/certs/clientkey.pem

# client specifics

CMD /usr/local/bin/envoy -c /etc/envoy.yaml --service-cluster client
# -l debug for DEBUG
