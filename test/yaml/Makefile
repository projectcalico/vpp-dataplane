include ../../common.mk

all:  iperf-image iperf3-image iperf3-vcl-image wrk-image nginx-image testpmd-image
push: iperf-push  iperf3-push  iperf3-vcl-push  wrk-push  nginx-push  testpmd-push

nginx-image:
	head -c 4K /dev/urandom > ./nginx/4096
	head -c 2M /dev/urandom > ./nginx/2MB
	head -c 600 /dev/urandom > ./nginx/600
	docker build $(DOCKER_BUILD_ARGS) -t calicovpp/test-nginx -f ./nginx/Dockerfile ./nginx
	rm ./nginx/4096
	rm ./nginx/2MB
	rm ./nginx/600

scalepods-image:
	cd scalepods && go build
	docker build $(DOCKER_BUILD_ARGS) -t calicovpp/test-scalepods ./scalepods

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
	for f in libvcl_ldpreload.so libvppcom.so.23.10 libvlibmemoryclient.so.23.10 \
	        libsvm.so.23.10 libvppinfra.so.23.10 libvlibapi.so.23.10 ; do \
		cp ${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/$${f} ./iperf3-vcl/ ; \
	done
	docker build $(DOCKER_BUILD_ARGS) -t calicovpp/test-iperf3-vcl -f ./iperf3-vcl/Dockerfile ./iperf3-vcl

.PHONY: trex-image-buildenv
trex-image-buildenv:
	docker build $(DOCKER_BUILD_ARGS) \
		-t calicovpp/test-trex-build:latest -f ./trex/build.Dockerfile ./trex
	docker run \
		--net=host --rm \
		-e BUILD_DIR=$(CURDIR) \
		-v $(CURDIR):$(CURDIR):delegated \
		--user $$(id -u):$$(id -g) \
		calicovpp/test-trex-build:latest

.PHONY: trex-image
trex-image: trex-image-buildenv
	rm -rf ./trex/trex-bins
	mkdir ./trex/trex-bins
	cp ./trex_build/trex-core/linux_dpdk/build_dpdk/linux_dpdk/_t-rex-64 ./trex/trex-bins/t-rex-64
	cp ./trex_build/trex-core/linux_dpdk/build_dpdk/linux_dpdk/libbpf-64.so ./trex/trex-bins/libbpf-64.so
	cp -r ./trex_build/trex-core/scripts/automation/trex_control_plane/interactive ./trex/trex-bins/trex-interactive
	cp -r ./trex_build/trex-core/scripts/external_libs ./trex/trex-bins/trex-external_libs
	docker build $(DOCKER_BUILD_ARGS) \
		-t calicovpp/test-trex -f ./trex/Dockerfile ./trex

%-image:
	docker build $(DOCKER_BUILD_ARGS) -t calicovpp/test-$* -f ./$*/Dockerfile ./$*

%-push:
	docker push calicovpp/test-$*
