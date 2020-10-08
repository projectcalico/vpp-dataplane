
all: iperf-image iperf3-image wrk-image nginx-image

iperf-image:
	docker build -t sknat/iperf -f ./iperf/Dockerfile ./iperf

iperf3-image:
	docker build -t sknat/iperf3 -f ./iperf3/Dockerfile ./iperf3

nginx-image:
	head -c 4KB /dev/urandom > ./nginx/test_4k
	head -c 2MB /dev/urandom > ./nginx/test_2m
	docker build -t mra/nginx -f ./nginx/Dockerfile ./nginx
	rm ./nginx/test_4k
	rm ./nginx/test_2m

wrk-image:
	docker build -t mra/wrk -f ./wrk/Dockerfile ./wrk
