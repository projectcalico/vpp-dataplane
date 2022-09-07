# This makefile contains targets used by the CI

ABS_PATH = $(abspath $(shell pwd)/..)

#
# Build a 
#
# Create a container image image used to build the go code.
#
# We're building a hash of that list of dependencies (Go,...). That should give us a deterministic
# version identifier for any particular list of dependencies -- if, with a future agent version,
# the dependencies change, then that hash will change. We can use that to minimize downloads
# from external sources, and maximise re-use of the "dependencies" image for as long as dependencies
# remain stable.
#

BASE_IMAGE_BUILDER = ubuntu:20.04

# Compute hash to detect any changes and rebuild /push the image
DEPEND_HASH = $(shell echo "${BASE_IMAGE_BUILDER}-DOCKERFILE:$(shell md5sum Dockerfile.depend)" | md5sum | cut -f1 -d' ')
DEPEND_IMAGE = calicovpp/ci-builder:${DEPEND_HASH}

.PHONY: depend_image
depend-image: ## Make dependencies image. (Not required normally; is implied in making any other container image).
	# Try to pull an existing dependencies image; it's OK if none exists yet.
	@echo Building depend image
	docker image pull ${DEPEND_IMAGE} || /bin/true
	docker image inspect ${DEPEND_IMAGE} >/dev/null 2>/dev/null \
          || docker image build \
               -f ./Dockerfile.depend \
               --build-arg BASE_IMAGE=${BASE_IMAGE_BUILDER} \
               --tag ${DEPEND_IMAGE} \
	       ${ABS_PATH}/

# Push depend image to dockerhub
.PHONY: push-depend_image
push-depend-image:
	docker push ${DEPEND_IMAGE}

#
# go vet vpp dataplane code
#
.PHONY: go-vet
go-vet: depend-image
	@echo Building vpp-dataplane
	docker run -t --rm --name build_temp -v ${ABS_PATH}:/vpp-dataplane ${DEPEND_IMAGE} go vet ./...
