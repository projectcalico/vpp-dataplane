include ../../.ci/common.mk

.PHONY: run-integration-tests vpp-image mock-image build-tests

TAG ?= latest # Tag images with :$(TAG)

ifndef CI_BUILD
SUDO := sudo -E
endif

VPP_IMAGE := calicovpp/vpp:$(TAG)
POD_MOCK_IMAGE := calicovpp/vpp-test-pod-mock:latest

vpp-image:
	docker image inspect ${VPP_IMAGE} >/dev/null 2>&1 \
	  || $(MAKE) -C ../../vpp-manager image


mock-image:
	docker build --network=host -t ${POD_MOCK_IMAGE} images/pod-mock


# Build integration tests
build-tests:
	${DOCKER_RUN} go test -c ../../calico-vpp-agent/cni


run-integration-tests: build-tests mock-image vpp-image
	@echo "Running Integration tests..."
	@echo "Running Calico VPP Agent - CNI tests..."
	${SUDO} env "PATH=$$PATH" VPP_BINARY=/usr/bin/vpp INTEGRATION_TEST=. VPP_IMAGE="${VPP_IMAGE}" ./cni.test -test.v -test.run Integration

VPP_DEV_DIR ?= /repo/vpp-manager/vpp_build/build-root/install-vpp_debug-native
dev: build-tests mock-image
	${SUDO} env "PATH=$$PATH" \
	  VPP_BINARY=${VPP_DEV_DIR}/vpp/bin/vpp \
	  LD_LIBRARY_PATH="${VPP_DEV_DIR}/vpp/lib/x86_64-linux-gnu" \
	  INTEGRATION_TEST=. VPP_IMAGE="calicovpp/vpp:latest" ./cni.test -test.v -test.run Integration

