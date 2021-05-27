
all: iperf-image iperf3-image wrk-image nginx-image scalepods-image scalesvc-build

iperf-image:
	docker build -t sknat/iperf -f ./iperf/Dockerfile ./iperf

iperf3-image:
	docker build -t sknat/iperf3 -f ./iperf3/Dockerfile ./iperf3

nginx-image:
	head -c 4K /dev/urandom > ./nginx/4096
	head -c 2M /dev/urandom > ./nginx/2MB
	head -c 600 /dev/urandom > ./nginx/600
	docker build -t mra/nginx -f ./nginx/Dockerfile ./nginx
	rm ./nginx/4096
	rm ./nginx/2MB
	rm ./nginx/600

wrk-image:
	docker build -t mra/wrk -f ./wrk/Dockerfile ./wrk


scalepods-image:
	cd scalepods && go build
	docker build -t sknat/scalepods ./scalepods

scalesvc-build:
	cd scalesvc && go build
