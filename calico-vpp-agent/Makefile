.PHONY: all build gobgp image push

TAG ?= latest

all: build gobgp image

export GOOS=linux
GOBGP_DIR=$(shell go list -f '{{.Dir}}' -m github.com/osrg/gobgp)

build:
	go build -o ./cmd/calico-vpp-agent ./cmd
	go build -o ./cmd/felix-api-proxy ./cmd/api-proxy

gobgp:
	go build -o ./dep/gobgp $(GOBGP_DIR)/cmd/gobgp/

image: build gobgp
	docker build --pull -t calicovpp/node:$(TAG) .

push: image
	docker push calicovpp/node:$(TAG)

dev: build gobgp
	docker build --pull -t calicovpp/node:$(TAG) .
