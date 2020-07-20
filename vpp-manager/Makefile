.PHONY: all build image imageonly vpp vpp-build-env

VPPLINK_DIR=../vpplink
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

vpp: vpp-build-env
	bash $(VPPLINK_DIR)/binapi/vpp_clone_current.sh ./vpp_build
	docker run --rm \
		-v $(CURDIR):/root/vpp-manager \
		calicovpp/vpp-build:latest
	rm -f $(IMAGE_DIR)*.deb
	for pkg in vpp vpp-plugin-core vpp-plugin-dpdk libvppinfra ; do \
		cp vpp_build/build-root/$$pkg_*.deb $(IMAGE_DIR) ; \
	done

vpp-build-env:
	docker build \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp-build:latest images/ubuntu-build
