include ../common.mk

TAG ?= latest # Tag images with :$(TAG)
ALSO_LATEST ?= n # If 'y' also tag images with :latest
GENERATE_LOG_FILE=../vpplink/generated/generate.log
VERSION_FILE=version

.PHONY: all
all: image

bin:
	mkdir -p bin

.PHONY: build
build: bin
	${DOCKER_RUN} go build $(COVER_OPTS) -o ./bin/felix-api-proxy ./cmd/api-proxy
	${DOCKER_RUN} go build $(COVER_OPTS) -o ./bin/calico-vpp-agent ./cmd
	${DOCKER_RUN} go build -o ./bin/gobgp github.com/osrg/gobgp/v3/cmd/gobgp/

.PHONY: image
image: build
	@cat $(GENERATE_LOG_FILE) > $(VERSION_FILE)
	docker build $(DOCKER_BUILD_ARGS) --pull -t calicovpp/agent:$(TAG) .
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/agent:$(TAG) calicovpp/agent:latest; \
		docker tag calicovpp/agent:$(TAG) calicovpp/agent:prerelease; \
	fi

.PHONY: image-cov
image-cov: build-cov
	@cat $(GENERATE_LOG_FILE) > $(VERSION_FILE)
	docker build $(DOCKER_BUILD_ARGS) --pull -t calicovpp/agent:$(TAG) .

.PHONY: push
push: ${PUSH_DEP}
	set -e; for registry in ${REGISTRIES}; do \
		docker tag calicovpp/agent:$(TAG) $${registry}calicovpp/agent:$(TAG); \
		if [ "${ALSO_LATEST}" = "y" ]; then \
			docker tag calicovpp/agent:$(TAG) $${registry}calicovpp/agent:latest; \
			docker tag calicovpp/agent:$(TAG) $${registry}calicovpp/agent:prerelease; \
		fi; \
		docker push --all-tags $${registry}calicovpp/agent; \
	done

.PHONY: dev
dev: image

.PHONY: proto
proto:
	$(MAKE) -C proto $@
