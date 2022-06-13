
FELIX_VERSION ?= v3.23.0
CNI_PLUGIN_VERSION ?= v3.23.0
PROTOC_VERSION = 3.17.3

FELIX_REPO = https://raw.githubusercontent.com/projectcalico/calico/$(FELIX_VERSION)/felix
CNI_PLUGIN_REPO = https://raw.githubusercontent.com/projectcalico/calico/$(CNI_PLUGIN_VERSION)/cni-plugin

.PHONY: proto
proto:
#@curl $(FELIX_REPO)/proto/felixbackend.proto -O 2> /dev/null
	@curl $(CNI_PLUGIN_REPO)/pkg/dataplane/grpc/proto/cnibackend.proto -O 2> /dev/null
	@if [ "$(shell protoc --version)" != "libprotoc $(PROTOC_VERSION)" ]; then \
        echo "Warning : using protoc $(shell protoc --version)"; \
    fi
	@go generate

