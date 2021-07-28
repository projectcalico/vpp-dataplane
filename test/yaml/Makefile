
all: iperf-image iperf3-image wrk-image nginx-image scalepods-image scalesvc-build

nginx-image:
	head -c 4K /dev/urandom > ./nginx/4096
	head -c 2M /dev/urandom > ./nginx/2MB
	head -c 600 /dev/urandom > ./nginx/600
	docker build -t mra/nginx -f ./nginx/Dockerfile ./nginx
	rm ./nginx/4096
	rm ./nginx/2MB
	rm ./nginx/600

scalepods-image:
	cd scalepods && go build
	docker build -t sknat/scalepods ./scalepods

scalesvc-build:
	cd scalesvc && go build

iperf3-vcl-image:
	rm -f ./iperf3-vcl/*.so
	rm -f ./iperf3-vcl/*.so.*
	cp ${VPP_DIR}/build-root/build-vpp-native/vpp/lib/*.so ./iperf3-vcl/
	cp ${VPP_DIR}/build-root/build-vpp-native/vpp/lib/*.so.* ./iperf3-vcl/
	docker build -t sknat/iperf3-vcl -f ./iperf3-vcl/Dockerfile ./iperf3-vcl

%-image:
	docker build -t sknat/$* -f ./$*/Dockerfile ./$*
