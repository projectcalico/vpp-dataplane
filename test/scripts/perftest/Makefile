
all: iperf-image iperf3-image wrk-image nginx-image

iperf-image:
	docker build -t sknat/iperf -f ./iperf/Dockerfile ./iperf

iperf3-image:
	docker build -t sknat/iperf3 -f ./iperf3/Dockerfile ./iperf3

nginx-image:
	docker build -t mra/nginx -f ./nginx/Dockerfile ./nginx

wrk-image:
	docker build -t mra/wrk -f ./wrk/Dockerfile ./wrk
