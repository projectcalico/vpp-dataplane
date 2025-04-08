include ../common.mk

.PHONY: all build gobgp image push proto

TAG ?= latest # Tag images with :$(TAG)
ALSO_LATEST ?= n # If 'y' also tag images with :latest
GENERATE_LOG_FILE=../vpplink/generated/generate.log
VERSION_FILE=version

all: build gobgp image

bin:
	mkdir -p bin

.PHONY: felix-api-proxy
felix-api-proxy: bin
	${DOCKER_RUN} go build -o ./bin/felix-api-proxy ./cmd/api-proxy

build: felix-api-proxy bin
	${DOCKER_RUN} go build -o ./bin/calico-vpp-agent ./cmd

gobgp: bin
	${DOCKER_RUN} go build -o ./bin/gobgp github.com/osrg/gobgp/v3/cmd/gobgp/

image: build gobgp
	@echo "Image tag                   : $(TAG)"                         > $(VERSION_FILE)
	@echo "VPP-dataplane version       : $(shell git log -1 --oneline)" >> $(VERSION_FILE)
	@cat $(GENERATE_LOG_FILE)                                           >> $(VERSION_FILE)
	docker build --pull -t calicovpp/agent:$(TAG) .
	@if [ "${ALSO_LATEST}" = "y" ]; then \
		docker tag calicovpp/agent:$(TAG) calicovpp/agent:latest; \
		docker tag calicovpp/agent:$(TAG) calicovpp/agent:prerelease; \
	fi

push: ${PUSH_DEP}
	set -e; for registry in ${REGISTRIES}; do \
		docker tag calicovpp/agent:$(TAG) $${registry}calicovpp/agent:$(TAG); \
		if [ "${ALSO_LATEST}" = "y" ]; then \
			docker tag calicovpp/agent:$(TAG) $${registry}calicovpp/agent:latest; \
			docker tag calicovpp/agent:$(TAG) $${registry}calicovpp/agent:prerelease; \
		fi; \
		docker push --all-tags $${registry}calicovpp/agent; \
	done

dev: image

proto:
	$(MAKE) -C proto $@
