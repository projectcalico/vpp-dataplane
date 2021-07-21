.PHONY: all build image push imageonly vpp vpp-build-env dev eksimage clean clean-vpp

VPPLINK_DIR=../vpplink
INIT_EKS_IMAGE_DIR=images/init-eks/
DEV_IMAGE_DIR=images/dev/
IMAGE_DIR=images/ubuntu
VPPDEV_FILE=../test/scripts/vppdev.sh
GENERATE_LOG_FILE=../vpplink/binapi/vppapi/generate.log
VERSION_FILE=$(IMAGE_DIR)/version
TAG ?= latest # Tag images with :$(TAG)
ALSO_LATEST ?= n # If 'y' also tag images with :latest

all: image

build:
	GOOS=linux go build -o $(IMAGE_DIR)/vpp-manager

eksimage:
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/init-eks:$(TAG) $(INIT_EKS_IMAGE_DIR)

image: build vpp eksimage
	@cp $(VPPDEV_FILE) $(IMAGE_DIR)
	@echo "Image tag                   : $(TAG)"                         > $(VERSION_FILE)
	@echo "VPP-dataplane version       : $(shell git log -1 --oneline)" >> $(VERSION_FILE)
	@cat $(GENERATE_LOG_FILE)                                           >> $(VERSION_FILE)
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:latest; \
	fi

push: image
	docker push calicovpp/vpp:$(TAG)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker push calicovpp/vpp:latest; \
	fi

imageonly: build
	cp $(VPPDEV_FILE) $(IMAGE_DIR)
	docker build --pull \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)

clean: clean-vpp

clean-vpp:
	git -C vpp_build clean -ffdx

vpp: vpp-build-env
	rm -f ./vpp_build/build-root/*.deb
	rm -f ./vpp_build/build-root/*.buildinfo
	rm -f $(IMAGE_DIR)/*.deb
	bash $(VPPLINK_DIR)/binapi/vpp_clone_current.sh ./vpp_build
	docker run --rm \
		-e VPP_MGR_DIR=$(CURDIR) \
		-v $(CURDIR):$(CURDIR):delegated \
		--user $$(id -u):$$(id -g) \
		calicovpp/vpp-build:latest
	for pkg in vpp vpp-plugin-core vpp-plugin-dpdk libvppinfra vpp-dbg ; do \
		cp vpp_build/build-root/$$pkg_*.deb $(IMAGE_DIR) ; \
	done

vpp-build-env:
	docker build \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp-build:latest images/ubuntu-build

dev: build
	cp $(VPPDEV_FILE) $(DEV_IMAGE_DIR)
	docker build \
	  --build-arg http_proxy=${DOCKER_BUILD_PROXY} \
	  -t calicovpp/vpp:$(TAG) $(DEV_IMAGE_DIR)
