include ../common.mk

SHELL := /bin/bash

VPPLINK_DIR=../vpplink

INIT_EKS_IMAGE_DIR=images/init-eks
DEV_IMAGE_DIR=images/dev
IMAGE_DIR=images/ubuntu
VCLSIDECAR_IMAGE_DIR=images/vclsidecar

VPPDEV_FILE=../test/scripts/vppdev.sh
GENERATE_LOG_FILE=../vpplink/generated/generate.log
TAG ?= latest # Tag images with :$(TAG)
ALSO_LATEST ?= n # If 'y' also tag images with :latest
VPP_DIR ?= $(CURDIR)/vpp_build

# temporary directory to build VPP in
VERSION_FILE=$(VPP_DIR)/calicovppversion

# BASE allows to override the VPP base commit in vpp_clone_current.sh
BASE ?=

VPP_REL_DEB_LIST = \
	$(VPP_DIR)/build-root/debs/release/vpp_*.deb \
	$(VPP_DIR)/build-root/debs/release/vpp-plugin-core_*.deb \
	$(VPP_DIR)/build-root/debs/release/vpp-plugin-dpdk_*.deb \
	$(VPP_DIR)/build-root/debs/release/libvppinfra_*.deb \
	$(VPP_DIR)/build-root/debs/release/vpp-dbg_*.deb \
	$(VPP_DIR)/build-root/debs/release/vpp-plugin-devtools_*.deb \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libsvm.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvppcom.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvlibapi.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvppinfra.so* \
	${VPP_DIR}/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvlibmemoryclient.so* \
	${VPP_DIR}/extras/libmemif/release/install/lib/libmemif.so \

VPP_DBG_DEB_LIST = \
	$(VPP_DIR)/build-root/debs/debug/vpp_*.deb \
	$(VPP_DIR)/build-root/debs/debug/vpp-plugin-core_*.deb \
	$(VPP_DIR)/build-root/debs/debug/vpp-plugin-dpdk_*.deb \
	$(VPP_DIR)/build-root/debs/debug/libvppinfra_*.deb \
	$(VPP_DIR)/build-root/debs/debug/vpp-dbg_*.deb \
	$(VPP_DIR)/build-root/debs/debug/vpp-plugin-devtools_*.deb \
	${VPP_DIR}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so* \
	${VPP_DIR}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libsvm.so* \
	${VPP_DIR}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvppcom.so* \
	${VPP_DIR}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvlibapi.so* \
	${VPP_DIR}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvppinfra.so* \
	${VPP_DIR}/build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvlibmemoryclient.so* \
	${VPP_DIR}/extras/libmemif/debug/install/lib/libmemif.so \

PATCHES = $(sort $(wildcard $(VPPLINK_DIR)/generated/patches/*.patch))
VPP_HASH = $(shell md5sum \
	$(VPPLINK_DIR)/generated/vpp_clone_current.sh \
	${PATCHES} \
	<(echo '$(subst $(VPP_DIR),,$(VPP_REL_DEB_LIST))') \
	<(echo '$(subst $(VPP_DIR),,$(VPP_DBG_DEB_LIST))') \
	<(echo '${BASE}') \
	| cut -f1 -d' ' | md5sum | cut -f1 -d' ')
VPP_TARBALL = vpp-${VPP_HASH}.tar

.PHONY: all
all: image

.PHONY: build
build:
	mkdir -p $(IMAGE_DIR)/bin
	cp $(VPPDEV_FILE) $(IMAGE_DIR)/bin/vppdev.sh
	${DOCKER_RUN} go build -o $(IMAGE_DIR)/bin/vpp-manager

.PHONY: eks-image
eks-image:
	docker build --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/init-eks:$(TAG) $(INIT_EKS_IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/init-eks:$(TAG) calicovpp/init-eks:latest; \
		docker tag calicovpp/init-eks:$(TAG) calicovpp/init-eks:prerelease; \
	fi

.PHONY: vclsidecar-image
vclsidecar-image: ${VPP_TARBALL}
	rm -rf $(VCLSIDECAR_IMAGE_DIR)/artifacts
	tar -xvf ${VPP_TARBALL} -C $(VCLSIDECAR_IMAGE_DIR)
	docker build -t calicovpp/vclsidecar:$(TAG) ${VCLSIDECAR_IMAGE_DIR}
	docker build -t calicovpp/vclsidecar:dbg-$(TAG) -f ${VCLSIDECAR_IMAGE_DIR}/Dockerfile.debug ${VCLSIDECAR_IMAGE_DIR}
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vclsidecar:$(TAG) calicovpp/vclsidecar:latest; \
		docker tag calicovpp/vclsidecar:$(TAG) calicovpp/vclsidecar:prerelease; \
	fi
	rm -rf $(VCLSIDECAR_IMAGE_DIR)/artifacts

.PHONY: vpp-image
vpp-image: build ${VPP_TARBALL}
	rm -rf $(IMAGE_DIR)/artifacts
	tar -xvf ${VPP_TARBALL} -C $(IMAGE_DIR)
	docker build --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg WITH_GDB=${WITH_GDB} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)
	docker build --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--build-arg WITH_GDB=${WITH_GDB} \
		-t calicovpp/vpp:dbg-$(TAG) -f $(IMAGE_DIR)/Dockerfile.debug $(IMAGE_DIR)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:latest; \
		docker tag calicovpp/vpp:$(TAG) calicovpp/vpp:prerelease; \
	fi
	rm -rf $(IMAGE_DIR)/artifacts

.PHONY: image
image: vpp-image eks-image vclsidecar-image

.PHONY: push
push: ${PUSH_DEP}
	set -e; for registry in ${REGISTRIES}; do \
		docker tag calicovpp/vpp:$(TAG) $${registry}calicovpp/vpp:$(TAG); \
		docker tag calicovpp/vpp:dbg-$(TAG) $${registry}calicovpp/vpp:dbg-$(TAG); \
		docker tag calicovpp/init-eks:$(TAG) $${registry}calicovpp/init-eks:$(TAG); \
		docker tag calicovpp/vclsidecar:$(TAG) $${registry}calicovpp/vclsidecar:$(TAG); \
		docker tag calicovpp/vclsidecar:dbg-$(TAG) $${registry}calicovpp/vclsidecar:dbg-$(TAG); \
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

.PHONY: vpp
vpp: clone-vpp vpp-build-env version-file
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
	rm -rf $(CURDIR)/artifacts
	mkdir -p $(CURDIR)/artifacts/debug
	mkdir -p $(CURDIR)/artifacts/release
	cp $(VPP_DBG_DEB_LIST) $(CURDIR)/artifacts/debug
	cp $(VPP_REL_DEB_LIST) $(CURDIR)/artifacts/release
	cp $(VERSION_FILE) $(CURDIR)/artifacts/debug
	cp $(VERSION_FILE) $(CURDIR)/artifacts/release

	tar --overwrite -cvf ${VPP_TARBALL} -C $(CURDIR) artifacts
	echo "Built ${VPP_TARBALL}"
	rm -rf $(CURDIR)/artifacts
ifdef CI_BUILD
	aws s3api put-object \
		--bucket ${VPP_BUCKET} \
		--key ${VPP_TARBALL} \
		--body ${VPP_TARBALL}
endif

${VPP_TARBALL}:
ifdef CI_BUILD
	aws s3api get-object \
		--bucket ${VPP_BUCKET} \
		--key ${VPP_TARBALL} \
		${VPP_TARBALL} \
	|| $(MAKE) vpp
else
	test -f ${VPP_TARBALL} \
	|| $(MAKE) vpp
endif

.PHONY: version-file
version-file:
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
	docker build --network=host \
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
