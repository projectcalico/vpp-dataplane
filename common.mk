VPP_DATAPLANE_DIR = $(shell git rev-parse --show-toplevel)

DEPEND_BASE = calicovpp/ci-builder
VPP_BUCKET = calico-vpp-ci-artefacts

export GOOS ?= linux

# Docker option
# push dependency
PUSH_DEP := image

REGISTRIES := docker.io/

# CI specific variables
ifdef CODEBUILD_BUILD_NUMBER
	# Define variable when building for CI
	CI_BUILD = 1
endif

ifdef COVER
	COVER_OPTS = -cover -covermode=atomic
else
	COVER_OPTS :=
endif

ifdef CI_BUILD
	export CI_BUILD
	GOFLAGS := -buildvcs=false

	# We make binaries static executable so that they are portable if they run outside of the calico container
	# where we have less control on the env and glibc version.
	# this is especially import for felix-api-proxy
	DOCKER_OPTS  = -e CI_BUILD=1 -e GOFLAGS=${GOFLAGS}
	DOCKER_OPTS += -e CGO_ENABLED=0
	DOCKER_OPTS += --user $$(id -u):$$(id -g)
	DOCKER_OPTS += -w /vpp-dataplane/$(shell git rev-parse --show-prefix)
	DOCKER_OPTS += -v $(VPP_DATAPLANE_DIR):/vpp-dataplane
	DOCKER_RUN = docker run -t --rm --name build_temp ${DOCKER_OPTS} calicovpp/ci-builder:latest

	PUSH_DEP :=

    # REGISTRY_PRIV may be defined in the CI environment
	REGISTRIES += ${REGISTRY_PRIV}
else
	DOCKER_RUN = CGO_ENABLED=0 GOFLAGS=${GOFLAGS}
endif

TAG = $(shell git describe --always --abbrev=40 --dirty)
ifeq (${CODEBUILD_WEBHOOK_TRIGGER},branch/master)
	ALSO_LATEST := y
endif

CLUSTER_NAME ?= kind-$(shell whoami)-$(shell git describe --always --abbrev=4)
DOCKER_BUILD_ARGS =  --network=host
DOCKER_BUILD_ARGS += --build-arg http_proxy=${DOCKER_BUILD_PROXY}
DOCKER_BUILD_ARGS += --build-arg https_proxy=${DOCKER_BUILD_PROXY}
DOCKER_BUILD_ARGS += --build-arg GIT_COMMIT="$(shell git log -1 --oneline)"
