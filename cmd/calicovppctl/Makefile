include ../../common.mk

BIN_DIR = $(VPP_DATAPLANE_DIR)/bin
SNAPSHOTTER_ENABLED := $(shell docker info -f '{{json .DriverStatus }}' | grep snapshotter)

.PHONY: bin
bin:
	@mkdir -p $(BIN_DIR)

.PHONY: build
build: bin
	${DOCKER_RUN} go build -o $(BIN_DIR)/calicovppctl .

.PHONY: image
image:
ifndef CI_BUILD
ifneq ($(SNAPSHOTTER_ENABLED),)
	docker build $(DOCKER_BUILD_ARGS) \
		--platform linux/amd64 \
		-t calicovpp/ctl:$(TAG) .
else
	@echo
	@echo "Will not build as calicovpp/ctl image as Multi-platform is not supported for the docker driver."
	@echo "use the following if you still want to build calicovpp/ctl"
	@echo "  echo '{"features": {"containerd-snapshotter": true}}' | sudo tee /etc/docker/daemon.json && sudo service docker restart"
	@echo "or"
	@echo "  make push"
	@echo
endif #SNAPSHOTTER_ENABLED
endif #CI_BUILD

.PHONY: push
push: ${PUSH_DEP}
	docker buildx create \
		--name vppctlbuilder \
		--driver docker-container \
		--use
	docker buildx build $(DOCKER_BUILD_ARGS) \
		--platform linux/arm64,linux/amd64 \
		--push \
		$(foreach registry,$(REGISTRIES),-t $(registry)calicovpp/ctl:$(TAG)) \
		$(if $(ALSO_LATEST),$(foreach registry,$(REGISTRIES),-t $(registry)calicovpp/ctl:latest)) \
		.
	docker buildx rm vppctlbuilder
