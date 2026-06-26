.PHONY: run
run:
	echo "scrape_configs:\n\
	- job_name: myapp\n\
	  scrape_interval: 10s\n\
	  static_configs:\n\
	  - targets:" > prometheus.yml
	for address in $$(kubectl get node -owide | grep -v NAME | awk '{print $$6}') ; do echo "    - $$address:8888" >> prometheus.yml ; done
	docker rm -f calicovpp-prometheus || true
	docker run --name calicovpp-prometheus --network host -p 9090:9090 -v $$PWD/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus &
.PHONY: stop
stop:
	docker rm -f calicovpp-prometheus || true
	rm -f prometheus.yml
