include ../common.mk

SHELL := /bin/bash

.PHONY: all build image push imageonly vpp vpp-build-env dev eksimage clean clean-vpp

VPPLINK_DIR=../vpplink
INIT_EKS_IMAGE_DIR=images/init-eks/
DEV_IMAGE_DIR=images/dev/
IMAGE_DIR=images/ubuntu
VPPDEV_FILE=../test/scripts/vppdev.sh
GENERATE_LOG_FILE=../vpplink/generated/generate.log
VERSION_FILE=$(IMAGE_DIR)/version
TAG ?= latest # Tag images with :$(TAG)
ALSO_LATEST ?= n # If 'y' also tag images with :latest
VPP_DIR ?= $(CURDIR)/vpp_build

PATCHES = $(sort $(wildcard $(VPPLINK_DIR)/generated/patches/*.patch))
VPP_HASH = $(shell md5sum <(md5sum $(VPPLINK_DIR)/generated/vpp_clone_current.sh ${PATCHES}) | cut -f 1 -d' ')
VPP_TARBALL = vpp-${VPP_HASH}.tgz

all: image

build:
	${DOCKER_RUN} go build -o $(IMAGE_DIR)/vpp-manager

# docker --squash is an experimental feature,
# it requires to do the following to work :
# echo '{"experimental": true}' | sudo tee /etc/docker/daemon.json

eksimage:
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/init-eks:$(TAG) $(INIT_EKS_IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/init-eks:$(TAG) calicovpp/init-eks:latest; \
		docker tag calicovpp/init-eks:$(TAG) calicovpp/init-eks:prerelease; \
	fi

image: build ${VPP_TARBALL} eksimage
	@cp $(VPPDEV_FILE) $(IMAGE_DIR)
	@echo "Image tag                   : $(TAG)"                         > $(VERSION_FILE)
	@echo "VPP-dataplane version       : $(shell git log -1 --oneline)" >> $(VERSION_FILE)
	@cat $(GENERATE_LOG_FILE)                                           >> $(VERSION_FILE)
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg WITH_GDB=${WITH_GDB} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:latest; \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:prerelease; \
	fi

push: ${PUSH_DEP}
	set -e; for registry in ${REGISTRIES}; do \
		docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:$(TAG); \
		docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:$(TAG); \
		\
		if [ "${ALSO_LATEST}" = "y" ]; then \
			docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:latest; \
			docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:prerelease; \
			\
			docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:latest; \
			docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:prerelease; \
		fi; \
		docker push --all-tags $${registry}calicovpp/vpp; \
		docker push --all-tags $${registry}calicovpp/init-eks; \
	done

imageonly: build
	cp $(VPPDEV_FILE) $(IMAGE_DIR)
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg https_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)

clean: clean-vpp

clone-vpp:
	BASE=$(BASE) bash $(VPPLINK_DIR)/generated/vpp_clone_current.sh ./vpp_build

clean-vpp:
	git -C $(VPP_DIR) clean -ffdx || true; \
	rm -f $(VPP_DIR)/build-root/*.deb; \
	rm -f $(VPP_DIR)/build-root/*.buildinfo; \
	rm -f $(IMAGE_DIR)/*.deb; \

rebuild-vpp: vpp-build-env
	docker run --rm \
		-e VPP_DIR=$(VPP_DIR) \
		-v $(VPP_DIR):$(VPP_DIR):delegated \
		--user $$(id -u):$$(id -g) \
		--env NO_BUILD_DEBS=true \
		--env HTTP_PROXY=$(HTTP_PROXY) \
		--env HTTPS_PROXY=$(HTTPS_PROXY) \
		--env http_proxy=$(http_proxy) \
		--env https_proxy=$(https_proxy) \
		--network=host \
		calicovpp/vpp-build:latest

vpp: clone-vpp vpp-build-env
	docker run --rm \
		-e VPP_DIR=$(VPP_DIR) \
		-v $(VPP_DIR):$(VPP_DIR):delegated \
		--user $$(id -u):$$(id -g) \
		--network=host \
		--env HTTP_PROXY=$(HTTP_PROXY) \
		--env HTTPS_PROXY=$(HTTPS_PROXY) \
		--env http_proxy=$(http_proxy) \
		--env https_proxy=$(https_proxy) \
		calicovpp/vpp-build:latest

	for pkg in vpp vpp-plugin-core vpp-plugin-dpdk libvppinfra vpp-dbg ; do \
		cp $(VPP_DIR)/build-root/$$pkg_*.deb $(IMAGE_DIR) ; \
	done
ifdef CI_BUILD
	find $(IMAGE_DIR) -type f -name '*.deb' -printf "%P\n"  | tar -czvf ${VPP_TARBALL} -C $(IMAGE_DIR) -T -
	aws s3api put-object --bucket ${VPP_BUCKET} --key ${VPP_TARBALL} --body ${VPP_TARBALL}
endif

${VPP_TARBALL}:
ifdef CI_BUILD
	mkdir -p ${IMAGE_DIR}
	aws s3api get-object --bucket ${VPP_BUCKET} --key ${VPP_TARBALL} ${VPP_TARBALL} \
	  && tar xzvf ${VPP_TARBALL} -C ${IMAGE_DIR} \
	  || $(MAKE) vpp
else
	$(MAKE) vpp
endif

vpp-build-env:
	docker build --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg https_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp-build:latest images/ubuntu-build

dev: build
	cp $(VPPDEV_FILE) $(DEV_IMAGE_DIR)
	docker build --squash --network=host \
	  --build-arg http_proxy=${DOCKER_BUILD_PROXY} \
	  --build-arg https_proxy=${DOCKER_BUILD_PROXY} \
	  --build-arg WITH_GDB=${WITH_GDB} \
	  -t calicovpp/vpp:$(TAG) $(DEV_IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:latest; \
	fi

vpp-hash:
	@echo VPP hash: ${VPP_HASH}
