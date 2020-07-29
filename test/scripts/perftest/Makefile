
all: iperf-image iperf3-image

iperf-image:
	docker build -t sknat/iperf -f ./iperf/Dockerfile ./iperf

iperf3-image:
	docker build -t sknat/iperf3 -f ./iperf3/Dockerfile ./iperf3
