CUR_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_DIR = $(shell pwd | sed  -E 's/(^.+vpp-dataplane).*$$/\1/')
ROOT_DIR = $(shell pwd | sed  -E 's/(^.+vpp-dataplane).*$$/\1/')
SUB_DIR = $(shell pwd | sed  -E 's/^.+vpp-dataplane\/(.*$$)/\1/')
THIS_DIR = $(notdir $(CUR_DIR))

DEPEND_BASE = calicovpp/ci-builder

VPP_BUCKET = calico-vpp-ci-artefacts

WITH_GDB ?= yes
export GOOS ?= linux

# Docker option
SQUASH := --squash
# push dependency
PUSH_DEP := image

# We make binaries static executable so that they are portable if they run outside of the calico container
# where we have less control on the env and glibc version.
# this is especially import for felix-api-proxy
CGO_ENABLED := 0

REGISTRIES := docker.io/

# CI specific variables
ifdef CODEBUILD_BUILD_NUMBER
	# Define variable when building for CI
	CI_BUILD = 1
endif

ifdef CI_BUILD
	export CI_BUILD
	GOFLAGS := -buildvcs=false

	DOCKER_OPTS  = -e CI_BUILD=1 -e GOFLAGS=${GOFLAGS}
	DOCKER_OPTS += -e CGO_ENABLED=${CGO_ENABLED}
	DOCKER_OPTS += --user $$(id -u):$$(id -g)
	DOCKER_OPTS += -w /vpp-dataplane/${SUB_DIR}
	DOCKER_OPTS += -v ${PROJECT_DIR}:/vpp-dataplane
	DOCKER_RUN = docker run -t --rm --name build_temp ${DOCKER_OPTS} calicovpp/ci-builder:latest
	SQUASH :=
	PUSH_DEP :=

        # REGISTRY_PRIV may be defined in the CI environment
	REGISTRIES += ${REGISTRY_PRIV}
else
	DOCKER_RUN = CGO_ENABLED=${CGO_ENABLED} GOFLAGS=${GOFLAGS}
endif

TAG = $(shell git rev-parse HEAD)
ifeq (${CODEBUILD_WEBHOOK_TRIGGER},branch/master)
	ALSO_LATEST := y
endif

CLUSTER_NAME ?= kind-$(shell whoami)-$(shell git describe --always --abbrev=4)
