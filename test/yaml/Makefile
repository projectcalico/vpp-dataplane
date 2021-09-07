
all:  iperf-image iperf3-image iperf3-vcl-image wrk-image nginx-image testpmd-image
push: iperf-push  iperf3-push  iperf3-vcl-push  wrk-push  nginx-push  testpmd-push

nginx-image:
	head -c 4K /dev/urandom > ./nginx/4096
	head -c 2M /dev/urandom > ./nginx/2MB
	head -c 600 /dev/urandom > ./nginx/600
	docker build -t calicovpp/test-nginx -f ./nginx/Dockerfile ./nginx
	rm ./nginx/4096
	rm ./nginx/2MB
	rm ./nginx/600

scalepods-image:
	cd scalepods && go build
	docker build -t calicovpp/test-scalepods ./scalepods

scalesvc-build:
	cd scalesvc && go build

iperf3-vcl-image:
	rm -f ./iperf3-vcl/*.so
	rm -f ./iperf3-vcl/*.so.*
	openssl genrsa -out ./iperf3-vcl/iperfcert.key
	openssl req -new -key ./iperf3-vcl/iperfcert.key \
				-out ./iperf3-vcl/iperfcert.csr
	openssl x509 -req -days 365 \
				 -in ./iperf3-vcl/iperfcert.csr \
				 -signkey ./iperf3-vcl/iperfcert.key \
				 -out ./iperf3-vcl/iperfcert.crt
	cp ${VPP_DIR}/build-root/build-vpp-native/vpp/lib/*.so ./iperf3-vcl/
	cp ${VPP_DIR}/build-root/build-vpp-native/vpp/lib/*.so.* ./iperf3-vcl/
	docker build -t calicovpp/test-iperf3-vcl -f ./iperf3-vcl/Dockerfile ./iperf3-vcl

%-image:
	docker build --network=host -t calicovpp/test-$* -f ./$*/Dockerfile ./$*

%-push:
	docker push calicovpp/test-$*
