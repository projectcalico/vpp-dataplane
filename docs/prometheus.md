# Prometheus howto

Create a `prometheus.yml` file:

````yaml
scrape_configs:
- job_name: myapp
  scrape_interval: 10s
  static_configs:
  - targets:
    - 172.18.0.2:8888
    - 172.18.0.3:8888
    - 172.18.0.4:8888
    - 172.18.0.6:8888
````

Replace the IP addrs under `targets` to the actual IP addrs of the worker nodes
in the cluster.

Run the prometheus container:

````bash
docker run --network host -p 9090:9090 \
 -v $PWD/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus &
````

Point browser to the IP addr of the node where prometheus is running:

````console
open http://<prometheus node IP addr>:9090
````

Another simple test to see if prometheus is working:

````bash
curl http://<worker node IP addr>:8888/metrics
````
