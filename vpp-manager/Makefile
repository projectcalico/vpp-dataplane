include ../common.mk

SHELL := /bin/bash

VPPLINK_DIR=../vpplink
SIDECARVCL_DIR=../test/yaml/sidecar-vcl
INIT_EKS_IMAGE_DIR=images/init-eks/
DEV_IMAGE_DIR=images/dev/
IMAGE_DIR=images/ubuntu
VPPDEV_FILE=../test/scripts/vppdev.sh
GENERATE_LOG_FILE=../vpplink/generated/generate.log
VERSION_FILE=$(IMAGE_DIR)/version
TAG ?= latest # Tag images with :$(TAG)
ALSO_LATEST ?= n # If 'y' also tag images with :latest
VPP_DIR ?= $(CURDIR)/vpp_build
# BASE allows to override the VPP base commit in vpp_clone_current.sh
BASE ?=

VPP_DEB_LIST = \
	$(VPP_DIR)/build-root/vpp_*.deb \
	$(VPP_DIR)/build-root/vpp-plugin-core_*.deb \
	$(VPP_DIR)/build-root/vpp-plugin-dpdk_*.deb \
	$(VPP_DIR)/build-root/libvppinfra_*.deb \
	$(VPP_DIR)/build-root/vpp-dbg_*.deb \
	$(VPP_DIR)/build-root/vpp-plugin-devtools_*.deb \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libsvm.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvppcom.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvlibapi.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvppinfra.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvlibmemoryclient.so* \
	${VPP_DIR}/extras/libmemif/build/lib/libmemif.so \

PATCHES = $(sort $(wildcard $(VPPLINK_DIR)/generated/patches/*.patch))
VPP_HASH = $(shell md5sum \
	$(VPPLINK_DIR)/generated/vpp_clone_current.sh \
	${PATCHES} \
	<(echo '${VPP_DEB_LIST}') \
	<(echo '${BASE}') \
	| md5sum | cut -f1 -d' ')
VPP_TARBALL = vpp-${VPP_HASH}.tgz

.PHONY: all
all: image

.PHONY: build
build:
	${DOCKER_RUN} go build -o $(IMAGE_DIR)/vpp-manager

# docker --squash is an experimental feature,
# it requires to do the following to work :
# echo '{"experimental": true}' | sudo tee /etc/docker/daemon.json

.PHONY: eksimage
eksimage:
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/init-eks:$(TAG) $(INIT_EKS_IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/init-eks:$(TAG) calicovpp/init-eks:latest; \
		docker tag calicovpp/init-eks:$(TAG) calicovpp/init-eks:prerelease; \
	fi

.PHONY: sidecar-vcl-image
sidecar-vcl-image: ${VPP_TARBALL}
	cp ${IMAGE_DIR}/libmemif.so \
		${IMAGE_DIR}/libvcl_ldpreload.so \
		${IMAGE_DIR}/libvppcom.so \
		${IMAGE_DIR}/libvlibmemoryclient.so \
		${IMAGE_DIR}/libsvm.so \
		${IMAGE_DIR}/libvppinfra.so \
		${IMAGE_DIR}/libvlibapi.so \
		${VERSION_FILE} \
		${SIDECARVCL_DIR}
	docker build -t calicovpp/vclsidecar:$(TAG) -f ${SIDECARVCL_DIR}/Dockerfile ${SIDECARVCL_DIR}
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vclsidecar:$(TAG) calicovpp/vclsidecar:latest; \
		docker tag calicovpp/vclsidecar:$(TAG) calicovpp/vclsidecar:prerelease; \
	fi
	rm -f ${SIDECARVCL_DIR}/lib*.so
	rm -f ${SIDECARVCL_DIR}/version

.PHONY: image
image: build ${VPP_TARBALL} eksimage sidecar-vcl-image
	@cp $(VPPDEV_FILE) $(IMAGE_DIR)
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg WITH_GDB=${WITH_GDB} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:latest; \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:prerelease; \
	fi

.PHONY: push
push: ${PUSH_DEP}
	set -e; for registry in ${REGISTRIES}; do \
		docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:$(TAG); \
		docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:$(TAG); \
		docker tag calicovpp/vclsidecar:$(TAG) $${registry}calicovpp/vclsidecar:$(TAG); \
		\
		if [ "${ALSO_LATEST}" = "y" ]; then \
			docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:latest; \
			docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:prerelease; \
			\
			docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:latest; \
			docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:prerelease; \
			\
			docker tag calicovpp/vclsidecar:$(TAG) $${registry}calicovpp/vclsidecar:latest; \
			docker tag calicovpp/vclsidecar:$(TAG) $${registry}calicovpp/vclsidecar:prerelease; \
		fi; \
		docker push --all-tags $${registry}calicovpp/vpp; \
		docker push --all-tags $${registry}calicovpp/init-eks; \
		docker push --all-tags $${registry}calicovpp/vclsidecar; \
	done

.PHONY: imageonly
imageonly: build
	cp $(VPPDEV_FILE) $(IMAGE_DIR)
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg https_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)

.PHONY: clean
clean: clean-vpp

.PHONY: clone-vpp
clone-vpp:
	BASE=$(BASE) bash $(VPPLINK_DIR)/generated/vpp_clone_current.sh ./vpp_build

.PHONY: clean-vpp
clean-vpp:
	git -C $(VPP_DIR) clean -ffdx || true
	rm -f $(VPP_DIR)/build-root/*.deb
	rm -f $(VPP_DIR)/build-root/*.buildinfo

.PHONY: rebuild-vpp
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

.PHONY: vpp
vpp: clone-vpp vpp-build-env
	rm -f $(IMAGE_DIR)/*.deb
	rm -f $(IMAGE_DIR)/*.so*
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
	cp $(VPP_DEB_LIST) $(IMAGE_DIR)

	find $(IMAGE_DIR) -type f \( -name '*.deb' -o -name '*.so' \) -printf "%P\n" | \
		tar -czvf ${VPP_TARBALL} -C $(IMAGE_DIR) -T -
ifdef CI_BUILD
	aws s3api put-object \
		--bucket ${VPP_BUCKET} \
		--key ${VPP_TARBALL} \
		--body ${VPP_TARBALL}
endif

${VPP_TARBALL}: ${VERSION_FILE}
ifdef CI_BUILD
	mkdir -p ${IMAGE_DIR}
	aws s3api get-object \
		--bucket ${VPP_BUCKET} \
		--key ${VPP_TARBALL} \
		${VPP_TARBALL} \
	&& tar xzvf ${VPP_TARBALL} -C ${IMAGE_DIR} \
	|| $(MAKE) vpp
else
	test -f ${VPP_TARBALL} || $(MAKE) vpp
endif

${VERSION_FILE}:
	@echo "Image tag                   : $(TAG)"                         > $(VERSION_FILE)
	@echo "VPP-dataplane version       : $(shell git log -1 --oneline)" >> $(VERSION_FILE)
	@cat $(GENERATE_LOG_FILE)                                           >> $(VERSION_FILE)

.PHONY: vpp-build-env
vpp-build-env:
	docker build --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg https_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp-build:latest images/ubuntu-build

.PHONY: dev
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

.PHONY: vpp-hash
vpp-hash:
	@echo VPP hash: ${VPP_HASH}
