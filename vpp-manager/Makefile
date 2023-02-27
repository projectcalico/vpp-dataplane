include ../.ci/common.mk

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

VPP_HASH = $(shell md5sum $(VPPLINK_DIR)/binapi/vpp_clone_current.sh | cut -f 1 -d' ')
VPP_TARBALL = vpp-${VPP_HASH}.tgz

all: image

export GOOS=linux
build:
	${DOCKER_RUN} go build -o $(IMAGE_DIR)/vpp-manager

# docker --squash is an experimental feature,
# it requires to do the following to work :
# echo '{"experimental": true}' | sudo tee /etc/docker/daemon.json

eksimage:
	docker build ${SQUASH} --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/init-eks:$(TAG) $(INIT_EKS_IMAGE_DIR)

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
	fi

push: ${PUSH_DEP}
	docker push calicovpp/vpp:$(TAG)
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker push calicovpp/vpp:latest; \
	fi

imageonly: build
	cp $(VPPDEV_FILE) $(IMAGE_DIR)
	docker build --squash --pull --network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		-t calicovpp/vpp:$(TAG) $(IMAGE_DIR)

clean: clean-vpp

clone-vpp:
	bash $(VPPLINK_DIR)/binapi/vpp_clone_current.sh ./vpp_build

clean-vpp:
	git -C vpp_build clean -ffdx || true
	rm -f ./vpp_build/build-root/*.deb
	rm -f ./vpp_build/build-root/*.buildinfo
	rm -f $(IMAGE_DIR)/*.deb

rebuild-vpp: vpp-build-env
	docker run --rm \
		-e VPP_MGR_DIR=$(CURDIR) \
		-v $(CURDIR):$(CURDIR):delegated \
		--user $$(id -u):$$(id -g) \
		--env NO_BUILD_DEBS=true \
		--network=host \
		calicovpp/vpp-build:latest

vpp: clone-vpp clean-vpp vpp-build-env
	docker run --rm \
		-e VPP_MGR_DIR=$(CURDIR) \
		-v $(CURDIR):$(CURDIR):delegated \
		--user $$(id -u):$$(id -g) \
		--network=host \
		calicovpp/vpp-build:latest
	for pkg in vpp vpp-plugin-core vpp-plugin-dpdk libvppinfra vpp-dbg ; do \
		cp vpp_build/build-root/$$pkg_*.deb $(IMAGE_DIR) ; \
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
		-t calicovpp/vpp-build:latest images/ubuntu-build

dev: build
	cp $(VPPDEV_FILE) $(DEV_IMAGE_DIR)
	docker build --squash --network=host \
	  --build-arg http_proxy=${DOCKER_BUILD_PROXY} \
	  --build-arg WITH_GDB=${WITH_GDB} \
	  -t calicovpp/vpp:$(TAG) $(DEV_IMAGE_DIR)
