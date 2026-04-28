include ../../common.mk

.PHONY: all
all: build

bin:
	mkdir -p bin

.PHONY: build
build: bin
	${DOCKER_RUN} go build $(COVER_OPTS) -o ./bin/felix-api-proxy ../../cmd/api-proxy
	${DOCKER_RUN} go build $(COVER_OPTS) -o ./bin/calico-vpp-agent ../../cmd/calico-vpp-agent
	${DOCKER_RUN} go build -o ./bin/gobgp github.com/osrg/gobgp/v3/cmd/gobgp/

.PHONY: proto
proto:
	$(MAKE) -C proto $@
