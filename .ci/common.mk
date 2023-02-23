CUR_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_DIR = $(shell pwd | sed  -E 's/(^.+vpp-dataplane).*$$/\1/')
ROOT_DIR = $(shell pwd | sed  -E 's/(^.+vpp-dataplane).*$$/\1/')
SUB_DIR = $(shell pwd | sed  -E 's/^.+vpp-dataplane\/(.*$$)/\1/')
THIS_DIR = $(notdir $(CUR_DIR))

DEPEND_BASE = calicovpp/ci-builder

VPP_BUCKET = calico-vpp-ci-artefacts

# Docker option
SQUASH := --squash
# push dependency
PUSH_DEP := image

# CI specific variables
ifdef CODEBUILD_BUILD_NUMBER
	# Define variable when building for CI
	CI_BUILD = 1
endif

ifdef CI_BUILD
	export CI_BUILD
	GOFLAGS := -buildvcs=false

	DOCKER_OPTS  = -e CI_BUILD=1 -e GOFLAGS=${GOFLAGS}
	DOCKER_OPTS += --user $$(id -u):$$(id -g)
	DOCKER_OPTS += -w /vpp-dataplane/${SUB_DIR}
	DOCKER_OPTS += -v ${PROJECT_DIR}:/vpp-dataplane
	DOCKER_RUN = docker run -t --rm --name build_temp ${DOCKER_OPTS} calicovpp/ci-builder:latest
	SQUASH :=
	PUSH_DEP :=
endif

TAG = $(shell git rev-parse HEAD)
ifeq (${CODEBUILD_WEBHOOK_TRIGGER},branch/master)
	ALSO_LATEST := y
endif
