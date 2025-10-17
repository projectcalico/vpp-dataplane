include ../../common.mk

BIN_DIR = $(VPP_DATAPLANE_DIR)/bin

.PHONY: bin
bin:
	@mkdir -p $(BIN_DIR)

.PHONY: build
build: bin
	${DOCKER_RUN} go build -o $(BIN_DIR)/calicovppctl .

.PHONY: image
image:
ifndef CI_BUILD
	docker build --network=host --build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--platform linux/arm64,linux/amd64 \
		-t calicovpp/ctl:$(TAG) .
endif

.PHONY: push
push: ${PUSH_DEP}
	docker buildx create \
		--name vppctlbuilder \
		--driver docker-container \
		--use
	docker buildx build \
		--network=host \
		--build-arg http_proxy=${DOCKER_BUILD_PROXY} \
		--platform linux/arm64,linux/amd64 \
		--push \
		$(foreach registry,$(REGISTRIES),-t $(registry)calicovpp/ctl:$(TAG)) \
		$(if $(ALSO_LATEST),$(foreach registry,$(REGISTRIES),-t $(registry)calicovpp/ctl:latest)) \
		.
	docker buildx rm vppctlbuilder
