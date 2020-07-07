.PHONY: all build gobgp image

all: build gobgp image

export GOOS=linux
GOBGP_DIR=$(shell go list -f '{{.Dir}}' -m github.com/osrg/gobgp)

build:
	go build -o ./cmd/calico-vpp-agent ./cmd

gobgp:
	go build -o ./dep/gobgp $(GOBGP_DIR)/cmd/gobgp/

image: build gobgp
	docker build --pull -t calicovpp/node:latest .
