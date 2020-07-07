.PHONY: all build image

VPPLINK_DIR=$(shell go list -f '{{.Dir}}' -m github.com/calico-vpp/vpplink)
IMAGE_DIR=images/ubuntu/

all: image

build:
	GOOS=linux go build -o $(IMAGE_DIR)/vpp-manager

image: build vpp
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:latest $(IMAGE_DIR)

imageonly: build
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:latest $(IMAGE_DIR)

vpp:
	bash $(VPPLINK_DIR)/binapi/vpp_clone_current.sh ./vpp_build
	cd vpp_build;                                          \
	make install-dep;                                      \
	git apply ../vpp-build.patch;                          \
	make rebuild-release;                                  \
	rm -f ./build-root/*.deb;                              \
	make pkg-deb;                                          \
	git apply -R ../vpp-build.patch;                       \
	rm -f ../$(IMAGE_DIR)*.deb;                              \
    cp ./build-root/vpp_*.deb ../$(IMAGE_DIR) ;               \
    cp ./build-root/vpp-plugin-core_*.deb ../$(IMAGE_DIR) ;   \
    cp ./build-root/vpp-plugin-dpdk_*.deb ../$(IMAGE_DIR) ;   \
    cp ./build-root/libvppinfra_*.deb ../$(IMAGE_DIR)
